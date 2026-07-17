//! Fullscreen overlay / destructive-confirm / stream-search 状态与逻辑。
//!
//! 从 `tui/mod.rs` 搬出（纯搬家，语义不变，仅按跨模块调用需要放宽 visibility）：
//! - [`Overlay`]：q/Esc 关闭的全屏表（files/procs/creds/audit/sessions/…）
//! - [`ConfirmAction`]：破坏性命令的 y/N 模态确认
//! - [`Toast`]：右下角瞬时通知（自动过期）
//! - `App::handle_overlay_key` / `handle_confirm_key` / `handle_search_key` /
//!   `build_confirm_description` / `toast`

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;

use crate::rest::Level;
use crate::types::{CredEntry, FileEntry, ProcEntry};

use super::{short, App};

/// What fullscreen overlay table to show (q/Esc dismisses).
#[derive(Default)]
pub(crate) enum Overlay {
    #[default]
    None,
    Files(Vec<FileEntry>),
    Procs(Vec<ProcEntry>),
    Creds(Vec<CredEntry>),
    Audit(Vec<crate::rest::AuditRow>),
    Sessions(ListState),
    /// 全字段会话详情；锚定 session id，render 时从 app.sess.list 实时查找。
    /// 本地数据 overlay（无 worker round-trip）：pending/age/ja3/ja4 等
    /// SessionView 里一直有但 Sessions 行列表丢弃的字段都在这展示。
    SessionDetail(String),
    Image(String, usize),
    /// 排队中（未投递）的任务表，来自 `GET /api/tasks`。
    Tasks(Vec<crate::rest::TaskRow>),
    Profile {
        loaded: bool,
        http_get_uri: String,
        http_post_uri: String,
        useragent: String,
    },
    AuditVerify {
        ok: bool,
        broken_at: Option<u64>,
    },
}

impl Overlay {
    pub(super) fn is_open(&self) -> bool {
        !matches!(self, Overlay::None)
    }
}

/// Pending destructive action awaiting y/N confirmation.
///
/// Set when the operator submits `/kill`, `/rm`, `/hide`, `/neutralize`, or
/// `/dump-lsass` — instead of dispatching immediately we pop a centered
/// confirm overlay (`render_confirm_overlay`) and only re-dispatch the stored
/// command once the operator presses `y`.
pub(crate) struct ConfirmAction {
    /// The full typed line to re-dispatch if confirmed (e.g. `/rm C:\\x`,
    /// `/hide 1234`). Re-dispatch reuses the normal `submit` path, with
    /// `App::confirmed` set so the intercept doesn't re-prompt.
    pub(super) cmd: String,
    /// Human-readable headline shown in the overlay body
    /// (e.g. "Delete file C:\\x on the target?").
    pub(super) description: String,
}

/// overlay/confirm/search 三态聚合（App 的 overlay 域字段 `ovl`）。
/// 从 App 平铺字段收拢为子结构：全屏 overlay、破坏性确认、事件流搜索。
#[derive(Default)]
pub(crate) struct OverlayState {
    /// 当前打开的全屏 overlay（[`Overlay::None`] = 无）。
    pub(super) overlay: Overlay,
    /// overlay 的滚动偏移（0 = 顶部）。overlay 打开或切换时复位为 0。
    /// PgUp/PgDn/↑/↓ 在 overlay 打开时调整它（取代 pane 滚动）。
    pub(super) scroll: usize,
    /// 待确认的破坏性命令（非 None 时渲染 confirm overlay，仅响应 y/n/Esc）。
    /// 详见 [`ConfirmAction`]。
    pub(super) confirm: Option<ConfirmAction>,
    /// 事件流搜索过滤。Some(q) = 只显示含 q 的行（大小写不敏感）。
    /// 底层 `stream: Vec<LogLine>` 不受影响（仍持有全部行），仅 display 层过滤。
    /// Ctrl+F 进入搜索输入态，Esc 退出并清空。
    pub(super) search_query: Option<String>,
    /// 搜索模式下的实时输入缓冲。Some(_) = 正在敲搜索词（按键直接进这里，
    /// 不进 pane 输入框）。Enter 落到 `search_query`，Esc 清空两者。
    pub(super) search_input: Option<String>,
}

impl OverlayState {
    /// 是否有全屏 overlay 打开。
    #[allow(dead_code)]
    pub(super) fn is_open(&self) -> bool {
        self.overlay.is_open()
    }
}

/// Transient toast notification — appears bottom-right, auto-dismisses after
/// a level-appropriate timeout. Unlike event-stream log lines (which persist
/// for audit), toasts are eye-level, ephemeral feedback: connection result,
/// command errors, destructive-action cancellation, etc. Capped at 5 visible
/// at once (oldest dropped) to prevent flooding the corner.
pub(crate) struct Toast {
    pub text: String,
    pub level: Level,
    pub created: Instant,
    pub duration: Duration,
}

impl Toast {
    /// Build a toast with a default duration: 3s for Info/Ok, 5s for Warn/Err
    /// (errors deserve more reading time).
    pub(super) fn new(text: impl Into<String>, level: Level) -> Self {
        let duration = match level {
            Level::Err | Level::Warn => Duration::from_secs(5),
            _ => Duration::from_secs(3),
        };
        Self {
            text: text.into(),
            level,
            created: Instant::now(),
            duration,
        }
    }

    pub(super) fn is_expired(&self) -> bool {
        self.created.elapsed() >= self.duration
    }
}

impl App {
    /// Push a transient toast notification (bottom-right, auto-dismisses).
    /// Capped at 5 — when exceeded the oldest is dropped. Call this alongside
    /// [`log`] for high-visibility feedback (connection result, command errors,
    /// destructive-action cancellation), or alone for purely transient messages.
    pub(super) fn toast(&mut self, text: impl Into<String>, level: Level) {
        self.toasts.push(Toast::new(text, level));
        if self.toasts.len() > 5 {
            self.toasts.remove(0);
        }
    }

    pub(super) fn handle_overlay_key(&mut self, key: KeyEvent) {
        // overlay 滚动页大小：取 overlay 可视高度的合理估值（与 render 的 inner
        // 高度一致：focused_pane_rect 去掉边框 2 + block padding）。最少 1。
        let page = self.panes.focused_rect.height.saturating_sub(4).max(1) as usize;
        match &mut self.ovl.overlay {
            Overlay::Sessions(state) => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    let i = state.selected().unwrap_or(0);
                    if i + 1 < self.sess.list.len() {
                        state.select(Some(i + 1));
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let i = state.selected().unwrap_or(0);
                    state.select(Some(i.saturating_sub(1)));
                }
                // PgUp/PgDn 滚动 Sessions 列表（↑/↓ 保留给选区导航）。
                // overlay_scroll 顶部锚定（0=顶）：PgUp 向顶（减），PgDn 向底（加）。
                KeyCode::PageUp => self.ovl.scroll = self.ovl.scroll.saturating_sub(page),
                KeyCode::PageDown => self.ovl.scroll = self.ovl.scroll.saturating_add(page),
                KeyCode::Enter => {
                    if let Some(i) = state.selected() {
                        if let Some(s) = self.sess.list.get(i) {
                            self.panes.tree
                                .set_session_id(self.panes.focused, Some(s.id.clone()));
                        }
                        if let Some(s) = self.sess.list.get(i) {
                            self.log(&format!("selected session {}", short(&s.id)), Level::Ok);
                        }
                    }
                    self.ovl.overlay = Overlay::None;
                }
                KeyCode::Char('q') | KeyCode::Esc => self.ovl.overlay = Overlay::None,
                _ => {}
            },
            Overlay::None => {}
            _ => match key.code {
                // 表格 overlay（Files/Procs/Creds/Audit/Tasks…）：↑/↓/PgUp/PgDn 滚动。
                // overlay_scroll 顶部锚定（0=顶）：↑/PgUp 向顶（减），↓/PgDn 向底（加）。
                // overlay_scroll 可超 max_scroll，render 会 clamp；上滚 saturating 到 0。
                KeyCode::PageUp | KeyCode::Up => {
                    self.ovl.scroll = self.ovl.scroll
                        .saturating_sub(if key.code == KeyCode::PageUp { page } else { 1 });
                }
                KeyCode::PageDown | KeyCode::Down => {
                    self.ovl.scroll =
                        self.ovl.scroll
                            .saturating_add(if key.code == KeyCode::PageDown {
                                page
                            } else {
                                1
                            });
                }
                KeyCode::Char('q') | KeyCode::Esc => self.ovl.overlay = Overlay::None,
                _ => {}
            },
        }
    }

    /// 搜索输入态的按键处理。Esc/Enter 退出输入态（Enter 落到 search_query，
    /// Esc 清空过滤）；其余字符追加到缓冲；Backspace 删尾。
    pub(super) fn handle_search_key(&mut self, key: KeyEvent) {
        let input = match self.ovl.search_input.as_mut() {
            Some(i) => i,
            None => return,
        };
        match key.code {
            KeyCode::Esc => {
                // 退出搜索：清空过滤 + 输入缓冲，回到全量显示。
                self.ovl.search_input = None;
                self.ovl.search_query = None;
            }
            KeyCode::Enter => {
                // 提交：落到 search_query（空串视为不过滤）。仍留在过滤态但退出
                // 输入态——Esc 才彻底清空。
                let q = std::mem::take(input);
                self.ovl.search_input = None;
                self.ovl.search_query = if q.trim().is_empty() { None } else { Some(q) };
            }
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl 组合键已在 handle_key 顶部拦截（仅 Ctrl+C 退出），这里只收
                // 裸字符。
                input.push(c);
            }
            _ => {}
        }
    }

    /// Confirm-overlay key handling. Returns true if the key was consumed
    /// (so the caller can short-circuit before any other key routing).
    ///
    /// `y` → re-dispatch the stored command via [`dispatch_line`] (bypasses
    ///   the intercept and history, since it's already there from the first
    ///   submit); `n`/`Esc` → cancel; anything else → ignored (must explicitly
    ///   confirm or deny).
    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> bool {
        let action = match self.ovl.confirm.take() {
            Some(a) => a,
            None => return false,
        };
        match key.code {
            KeyCode::Char('y') => {
                // 重派发存的原命令。不进 submit（避免重复 history + 再拦截）。
                self.dispatch_line(&action.cmd);
                self.ovl.confirm = None;
                true
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.log("cancelled", Level::Info);
                self.toast("cancelled", Level::Warn);
                self.ovl.confirm = None;
                true
            }
            _ => {
                // 未确认也未取消：把 action 放回去，继续等。
                self.ovl.confirm = Some(action);
                true // 仍吞掉该键（必须显式 y/n/Esc）
            }
        }
    }

    /// 构造破坏性命令的确认提示语。`generic` 是来自 [`DESTRUCTIVE_COMMANDS`]
    /// 的通用描述；这里按命令补充上下文（beacon id / 目标路径 / pid），让
    /// 操作员在 y 之前看到具体影响对象。
    ///
    /// 退化情况（无选中 beacon、解析失败）只回退到 generic 文案，不阻断确认流程。
    pub(super) fn build_confirm_description(&self, raw: &str, generic: &str) -> String {
        let trimmed = raw.trim();
        let (cmd, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((c, r)) => (c.to_ascii_lowercase(), r.trim()),
            None => (trimmed.to_ascii_lowercase(), ""),
        };
        match cmd.as_str() {
            "/kill" => {
                let sid = self
                    .current_session()
                    .map(|s| short(&s.id))
                    .unwrap_or_default();
                format!("Kill session {sid}? The implant will exit.")
            }
            "/rm" => {
                let path = rest.split_whitespace().next().unwrap_or("<path>");
                format!("Delete file {path} on the target? {generic}")
            }
            "/hide" => {
                let pid = rest.split_whitespace().next().unwrap_or("<pid>");
                format!("Hide process {pid} via kernel DKOM? {generic}")
            }
            "/neutralize" => {
                let pid = rest.split_whitespace().next().unwrap_or("<pid>");
                format!("Neutralize EDR callbacks for {pid}? {generic}")
            }
            "/dump-lsass" => {
                let pid = rest.split_whitespace().next().unwrap_or("<pid>");
                format!("Dump LSASS memory for pid {pid}? {generic}")
            }
            _ => generic.to_string(),
        }
    }
}
