//! Rendering for the fullscreen TUI.
//!
//! All `render_*` free functions plus the `render()` entry point live here;
//! `tui/mod.rs` owns App state and input handling. Pure move refactor — no
//! behaviour change. Functions read off `App` fields, which are `pub(super)`
//! for that reason.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Padding, Paragraph, Wrap};

use crate::theme;
use crate::types::{arch_str, SessionView};

use super::input::{self, filter_meta};
use super::panes;
use super::{fmt_age, short, App, Overlay};

pub(super) fn render(app: &mut App, frame: &mut ratatui::Frame) {
    let area = frame.area();
    // 记录本帧尺寸，handle_key 里 move_focus 用它替代硬编码的4 80×24。
    app.last_frame_size = area;
    // 清空上一帧的 view tab hit regions，render_pane 会重建。防止窗格关闭后残留。
    app.view_tab_rect.clear();
    // 清空上一帧的 session 行 hit regions，render_overlay 重建。
    app.session_row_rects.clear();
    // 清空上一帧的 per-pane SessionList 行 hit regions。
    app.pane_session_rows.clear();
    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(Paragraph::new("").style(theme::base_bg()), area);

    if area.height < 8 || area.width < 40 {
        let msg = Paragraph::new(" window too small — resize to at least 40x8 ")
            .style(theme::muted())
            .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    render_statusbar(frame, app, chunks[0]);
    // 窗格树区域：递归渲染每个叶。用 layout_full 一次遍历拿全 (id, rect, view, session)，
    // 避免之前每帧 clone 整棵树 + O(n²) 二次 leaves() 查找 view（P1-2）。
    let pane_area = chunks[1];
    let layouts = app.pane_tree.layout_full(pane_area);
    for (id, rect, view, session_id) in &layouts {
        let is_focused = *id == app.focused_pane;
        // 记录焦点窗格 rect，供 overlay 限制区域用（不再全屏遮挡其他窗格）。
        if is_focused {
            app.focused_pane_rect = *rect;
        }
        render_pane(frame, app, *id, *rect, is_focused, *view, session_id.as_deref());
    }
    render_input(frame, app, chunks[2]);

    // popup 是否打开由焦点窗格决定（per-pane）
    if app.focused_state().popup_open {
        render_popup(frame, app, chunks[2]);
    }
    // view picker：某窗格的视图选择菜单开着 → 在它的 tab 下方画小 popup。
    if app.view_picker.is_some() {
        render_view_picker(frame, app);
    }
    if app.overlay.is_open() {
        // overlay 限制在焦点窗格区域内（不再全屏遮挡其他窗格）。
        // 用 focused_pane_rect 让 overlay 只覆盖当前操作的窗格。
        render_overlay(frame, app, app.focused_pane_rect);
    }
}

/// 渲染单个窗格叶。
///
/// 顶部边框行改造成可点击的视图 tab bar（opencode 风格）：6 个 tab 横排，
/// 当前视图高亮（实心背景），其余 muted。每个 tab 的屏幕 Rect 记录到
/// `app.tab_hit_regions`，供 click 反查切换视图。
fn render_pane(
    frame: &mut ratatui::Frame,
    app: &mut App,
    id: usize,
    area: Rect,
    focused: bool,
    view: panes::PaneView,
    session_id: Option<&str>,
) {
    // ---- 边框 + 配色层次（P0 视觉改造）----
    // 焦点：Rounded 圆角 + accent 边框（醒目）。
    // hover：Rounded + accent_dim（次醒目）。
    // 普通：Rounded + surface2（接近背景色，相邻窗格的双线感自然消失，gitui 手法）。
    // 不再用 Thick 粗块（笨重）和 faint（太淡看不见）。
    let is_hovered = app.hover_pane == Some(id) && !focused;
    let (border_color, bg_color) = if focused {
        (theme::accent(), theme::surface())
    } else if is_hovered {
        (theme::accent_dim(), theme::base())
    } else {
        (theme::surface2(), theme::base())
    };

    // ---- 紧凑视图 tab：只画当前视图名 + ▾ 下拉指示 ----
    let tab_y = area.y;
    let tab_label = view.label();
    let picker_open = app
        .view_picker
        .as_ref()
        .is_some_and(|(pid, _)| *pid == id);
    let arrow = if picker_open { "▴" } else { "▾" };
    let tab_text = format!(" {tab_label} {arrow} ");
    let tab_w = tab_text.chars().count() as u16;
    let tab_x = area.x + 1;
    app.view_tab_rect.insert(
        id,
        Rect {
            x: tab_x,
            y: tab_y,
            width: tab_w,
            height: 1,
        },
    );
    // tab 高亮改柔和配色（P1）：surface1 背景 + text 前景，不再强反色刺眼。
    // 焦点窗格的 tab 用 accent 前景强化，其余用 text。
    let mut tab_spans: Vec<Span> = vec![Span::styled(
        tab_text,
        Style::default()
            .fg(if focused { theme::accent() } else { theme::text_color() })
            .bg(theme::surface1())
            .add_modifier(Modifier::BOLD),
    )];
    tab_spans.push(Span::styled(format!(" [{id}]"), theme::faint()));
    if let Some(sid) = session_id {
        let alias = app
            .sessions_meta
            .get(sid)
            .alias
            .clone()
            .unwrap_or_else(|| short(sid));
        tab_spans.push(Span::styled(format!(" · {alias}"), theme::faint()));
    }
    let off = app.pane_scroll.get(&id).copied().unwrap_or(0);
    if off > 0 {
        tab_spans.push(Span::styled(format!(" ↑{off}"), theme::warn()));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .title_top(Line::from(tab_spans))
        // P1 呼吸感：内容区加 1 列水平 padding，内容不再紧贴边框。
        .padding(Padding::horizontal(1))
        .style(Style::default().bg(bg_color).fg(theme::text_color()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match view {
        panes::PaneView::Console => {
            render_stream_content(frame, app, inner, id);
        }
        panes::PaneView::SessionList => {
            render_sessions_in_pane(frame, app, inner, id);
        }
        panes::PaneView::Files => {
            render_files_table(frame, inner, &app.files_view);
        }
        panes::PaneView::Procs => {
            render_procs_table(frame, inner, &app.procs_view);
        }
        panes::PaneView::Creds => {
            render_creds_table(frame, inner, &app.creds_view);
        }
        panes::PaneView::Topology => {
            render_topology_in_pane(frame, app, inner);
        }
    }
}

/// 事件流内容（无边框，边框由 render_pane 提供）。
/// 使用该窗格自己的 pane_scroll 居中滚动偏移（独立），回退到全局 stream_offset。
fn render_stream_content(frame: &mut ratatui::Frame, app: &App, area: Rect, pane_id: usize) {
    let pane_session = app.pane_tree.get_session_id(pane_id);
    let target_session = pane_session.as_ref();

    // Filter stream: include global logs (None) and logs matching target_session (supporting prefix matching)
    let pane_stream: Vec<&crate::rest::LogLine> = app.stream
        .iter()
        .filter(|l| {
            match (&l.session_id, target_session) {
                (None, _) => true,
                (Some(s1), Some(s2)) => s1 == s2 || s2.starts_with(s1) || s1.starts_with(s2),
                (Some(_), None) => false,
            }
        })
        .collect();

    // 使用该窗格自己的 scroll offset（独立滚动），不存在则用全局 stream_offset。
    let scroll_offset = app.pane_scroll.get(&pane_id).copied().unwrap_or(app.stream_offset);
    let height = area.height as usize;
    let total = pane_stream.len();
    let end = total.saturating_sub(scroll_offset);
    let start = end.saturating_sub(height);
    let visible = &pane_stream[start..end.min(total)];
    let lines: Vec<Line> = visible
        .iter()
        .map(|l| {
            // A11y-A2：marker 用级别专属形状符号（ℹ✓⚠✕），不再统一 ▎，
            // 色盲用户也能区分级别。后接空格保持视觉间距。
            let glyph = theme::level_glyph(l.level);
            Line::from(vec![
                Span::styled(format!("{glyph} "), theme::level_marker(l.level)),
                Span::styled(l.text.clone(), theme::level(l.level)),
            ])
        })
        .collect();
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// 在窗格里渲染 session 列表。逐行渲染 + 记录 hit regions 支持点击切换。
/// 当前选中的 session 行高亮（surface1 背景 + ▸ 标记），点击其他行切换 beacon。
fn render_sessions_in_pane(
    frame: &mut ratatui::Frame,
    app: &mut App,
    area: Rect,
    pane_id: usize,
) {
    if app.sessions.is_empty() {
        let para = Paragraph::new("· no beacons — waiting for sessions")
            .style(theme::faint())
            .alignment(Alignment::Center);
        frame.render_widget(para, area);
        return;
    }
    // 该窗格当前绑定的 session（用于高亮"当前调用的是哪个 beacon"）。
    let cur_sid = app.pane_tree.get_session_id(pane_id);
    let mut row_rects: Vec<(Rect, String)> = Vec::new();
    for (i, s) in app.sessions.iter().enumerate() {
        let row_y = area.y + i as u16;
        if row_y >= area.y + area.height {
            break; // 超出窗格截断
        }
        let row_rect = Rect {
            x: area.x,
            y: row_y,
            width: area.width,
            height: 1,
        };
        let is_current = cur_sid.as_deref() == Some(&s.id);
        row_rects.push((row_rect, s.id.clone()));

        let m = app.sessions_meta.get(&s.id);
        let star = if m.favorite { "★" } else { " " };
        let alias = m.alias.as_deref().unwrap_or("");
        let mark = if is_current { "▸ " } else { "  " };
        // 当前 session 行用 selected() 高亮（蓝色背景）——但只覆盖有内容的列，
        // 不填满整行（避免行尾一大坨色块）。行尾空白保持窗格背景。
        let sel = theme::selected();
        let sel_bg = sel.bg.unwrap_or(theme::base());
        let sel_fg = sel.fg.unwrap_or(theme::text_color());
        let mk = |color: ratatui::style::Color, text: String| -> Span<'_> {
            if is_current {
                Span::styled(
                    text,
                    Style::default()
                        .fg(sel_fg)
                        .bg(sel_bg)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(text, Style::default().fg(color))
            }
        };
        let line = Line::from(vec![
            mk(theme::mauve(), mark.to_string()),
            mk(theme::accent(), format!("{:8} ", short(&s.id))),
            mk(theme::text_color(), format!("{:14} ", s.hostname)),
            mk(theme::text_color(), format!("{:12} ", s.username)),
            mk(theme::warn(), star.to_string()),
            mk(theme::muted_color(), format!(" {alias}")),
        ]);
        if is_current {
            // 当前行：把内容 pad 到窗格满宽，让蓝色高亮填满整行长条。
            // 计算已有内容的字符数，补足空格（带 sel_bg 背景）。
            let content_len: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
            let pad = (area.width as usize).saturating_sub(content_len);
            let mut full_line = line;
            full_line.spans.push(Span::styled(
                " ".repeat(pad),
                Style::default().bg(sel_bg),
            ));
            frame.render_widget(Paragraph::new(full_line), row_rect);
        } else {
            frame.render_widget(Paragraph::new(line), row_rect);
        }
    }
    app.pane_session_rows.insert(pane_id, row_rects);
}

/// Render a file listing inside a pane leaf. Mirrors the fullscreen
/// `Overlay::Files` table (render.rs Files arm) but without its own border
/// block — the pane already supplies one via `render_pane`. Empty → hint.
fn render_files_table(frame: &mut ratatui::Frame, area: Rect, rows: &[crate::types::FileEntry]) {
    if rows.is_empty() {
        hint(frame, area, "(files — use /ls to populate)");
        return;
    }
    let header = ["NAME", "SIZE", "TYPE", "MODIFIED"];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|f| {
            vec![
                f.name.clone(),
                f.size.to_string(),
                if f.is_dir { "dir" } else { "file" }.into(),
                f.modified.clone(),
            ]
        })
        .collect();
    render_borderless_table(frame, area, &header, &body);
}

/// Render a process listing inside a pane leaf. Mirrors `Overlay::Procs`.
fn render_procs_table(frame: &mut ratatui::Frame, area: Rect, rows: &[crate::types::ProcEntry]) {
    if rows.is_empty() {
        hint(frame, area, "(procs — use /ps to populate)");
        return;
    }
    let header = ["PID", "PPID", "USER", "NAME"];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|p| {
            vec![
                p.pid.to_string(),
                p.ppid.to_string(),
                p.user.clone(),
                p.name.clone(),
            ]
        })
        .collect();
    render_borderless_table(frame, area, &header, &body);
}

/// Render a credential listing inside a pane leaf. Mirrors `Overlay::Creds`
/// (secret masking included).
fn render_creds_table(frame: &mut ratatui::Frame, area: Rect, rows: &[crate::types::CredEntry]) {
    if rows.is_empty() {
        hint(frame, area, "(creds — use /creds to populate)");
        return;
    }
    let header = ["SOURCE", "PRINCIPAL", "KIND", "SECRET"];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|c| {
            vec![
                c.source.clone(),
                c.principal.clone(),
                c.kind.label().into(),
                input::mask(&c.secret),
            ]
        })
        .collect();
    render_borderless_table(frame, area, &header, &body);
}

/// Render the session topology inside a pane leaf. Derives the same layered
/// layout `/topo` computes in the event stream, so the pane shows live topology
/// from `app.sessions` instead of a dead placeholder. With no sessions it falls
/// back to the hint.
fn render_topology_in_pane(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    if app.sessions.is_empty() {
        hint(frame, area, "(topology — no beacons)");
        return;
    }
    let nodes: Vec<(String, String)> = app
        .sessions
        .iter()
        .map(|s| {
            let label = app
                .sessions_meta
                .get(&s.id)
                .alias
                .clone()
                .unwrap_or_else(|| s.hostname.clone());
            (s.id.clone(), label)
        })
        .collect();
    let topo = super::topology::layout(&nodes, &[]);
    let mut lines: Vec<Line> = Vec::new();
    let max_y = topo.nodes.iter().map(|n| n.y).max().unwrap_or(0);
    for layer in 0..=max_y {
        let layer_nodes: Vec<&super::topology::TopoNode> =
            topo.nodes.iter().filter(|n| n.y == layer).collect();
        if layer_nodes.is_empty() {
            continue;
        }
        let node_strs: Vec<String> = layer_nodes
            .iter()
            .map(|n| {
                let mark = if n.is_beacon { "◆" } else { "◇" };
                format!("{mark} {}", n.label)
            })
            .collect();
        lines.push(Line::from(vec![Span::styled(
            format!("L{}  {}", layer, node_strs.join("  ")),
            theme::text(),
        )]));
    }
    if lines.is_empty() {
        hint(frame, area, "(topology — /topo for edges)");
    } else {
        frame.render_widget(Paragraph::new(lines), area);
    }
}

/// A table rendered WITHOUT its own border block (the pane supplies the border).
/// Mirrors the column widths used by the fullscreen overlay tables.
fn render_borderless_table(
    frame: &mut ratatui::Frame,
    area: Rect,
    header: &[&str],
    rows: &[Vec<String>],
) {
    use ratatui::widgets::{Cell, Row, Table};
    let header_row = Row::new(header.iter().map(|h| Cell::from(*h))).style(
        Style::default()
            .fg(theme::muted_color())
            .add_modifier(Modifier::BOLD),
    ).bottom_margin(1);
    let data_rows: Vec<Row> = rows
        .iter()
        .map(|r| Row::new(r.iter().cloned().map(|c| Cell::new(c).style(theme::text()))))
        .collect();
    let widths: Vec<Constraint> = match header.len() {
        4 => vec![
            Constraint::Percentage(32),
            Constraint::Percentage(14),
            Constraint::Percentage(18),
            Constraint::Percentage(36),
        ],
        _ => (0..header.len())
            .map(|_| Constraint::Percentage((100 / header.len()) as u16))
            .collect(),
    };
    let table = Table::new(data_rows, widths)
        .header(header_row)
        .highlight_style(theme::selected());
    frame.render_widget(table, area);
}

/// Dimmed hint shown when a pane view has no data yet. 加 · 前缀符号做视觉锚点，
/// 居中显示比左对齐更优雅（空状态是"等待操作员"，居中暗示"这里待填充"）。
fn hint(frame: &mut ratatui::Frame, area: Rect, msg: &str) {
    let para = Paragraph::new(format!("· {msg}"))
        .style(theme::faint())
        .alignment(Alignment::Center);
    frame.render_widget(para, area);
}

fn render_statusbar(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    // Header strip: solid background, brand on the left, status dot+label,
    // then dimmed session/beacon info.
    let (dot, dot_style, label) = if app.connected {
        ("●", Style::default().fg(theme::success()), "connected")
    } else {
        ("○", Style::default().fg(theme::danger()), "disconnected")
    };
    let beacon = match app.current_session() {
        Some(s) => {
            let mut buf = format!("{}@{} · {}", s.username, s.hostname, short(&s.id));
            if s.pending > 0 {
                buf.push_str(&format!(" · pend:{}", s.pending));
            }
            buf.push_str(&format!(" · {}", fmt_age(app.age_for(&s.id))));
            buf
        }
        None => "no beacon".to_string(),
    };
    // 三段式状态栏（P2 视觉改造）：左品牌+连接 · 中 beacon 上下文 · 右计数+模式。
    // 段间用 │ 竖线分隔，段内不同色相（左 brand、中 text、右 muted），层次分明。
    let mut spans = vec![
        // ---- 左段：品牌 + 连接状态 ----
        Span::styled(" nyx ", theme::brand()),
        Span::styled(dot, dot_style),
        Span::styled(format!(" {label} "), theme::muted()),
        Span::styled("│", Style::default().fg(theme::surface2())),
        // ---- 中段：当前 beacon 上下文 ----
        Span::styled(format!(" {beacon} "), theme::text()),
        Span::styled("│", Style::default().fg(theme::surface2())),
        // ---- 右段：计数 + 模式 ----
        Span::styled(
            format!(" {} ", app.sessions.len()),
            Style::default()
                .fg(theme::mauve())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("beacons ", theme::muted()),
    ];
    // prefix 模式指示器（UX-S5）：激活时在状态栏最右显示醒目标记。
    if app.tmux_prefix {
        spans.push(Span::styled("│", Style::default().fg(theme::surface2())));
        spans.push(Span::styled(
            " [PREFIX] ",
            Style::default()
                .fg(theme::warn())
                .add_modifier(Modifier::BOLD),
        ));
    }
    let line = Line::from(spans);
    frame.render_widget(Paragraph::new(line).style(theme::header_bg()), area);
}

fn render_input(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    // 输入栏：顶部圆角分隔线 + surface 底色。标题精简为 " input "。
    let block = Block::default()
        .borders(Borders::TOP)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::surface2()))
        .title(Span::styled(" input ", theme::muted()))
        .style(theme::input_bg())
        .padding(Padding::horizontal(2));
    // 关键：用 block.inner(area) 拿到去掉边框+padding 后的真实内容区。
    // 之前错误地用 area 原始值，导致 prompt 画在边框上、位置错乱。
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let (display, cursor_chars) = {
        let st = app.focused_state();
        (st.input.clone(), st.cursor)
    };

    // 目标 session 标签（UX-S1）：防误发。无 session 显示 "[no beacon]"。
    let tag_text = match app.current_session() {
        Some(s) => {
            let alias = app
                .sessions_meta
                .get(&s.id)
                .alias
                .clone()
                .unwrap_or_else(|| s.hostname.clone());
            format!("[{} {}] ", short(&s.id), alias)
        }
        None => "[no beacon] ".to_string(),
    };
    let is_empty = display.is_empty();
    let prompt = if is_empty {
        Paragraph::new(Line::from(vec![
            Span::styled(tag_text.clone(), theme::muted()),
            Span::styled("type a command, or / for menu", theme::faint()),
        ]))
        .style(theme::input_bg())
    } else {
        Paragraph::new(Line::from(vec![
            Span::styled(tag_text.clone(), theme::muted()),
            Span::styled(
                format!("❯ {display}"),
                Style::default().fg(theme::accent()),
            ),
        ]))
        .style(theme::input_bg())
    };
    frame.render_widget(prompt, inner);

    // 硬件光标定位。inner 已是去掉边框+padding 后的区域，光标相对 inner 算。
    // 非空状态：tag_text + "❯ "(2列) + cursor；空状态：光标停在 tag 后（无 ❯）。
    let tag_w = tag_text.chars().count() as u16;
    let prefix_w = if is_empty {
        tag_w
    } else {
        tag_w + 2 // "❯ " = ❯(1列) + space(1列)
    };
    let cursor_x = inner.x + prefix_w + cursor_chars as u16;
    frame.set_cursor_position((
        cursor_x.min(inner.x + inner.width.saturating_sub(1)),
        inner.y,
    ));
}

fn render_popup(frame: &mut ratatui::Frame, app: &mut App, input_area: Rect) {
    // Popup 也按焦点窗格渲染（per-pane）：只有当前焦点窗格的输入态
    // 处于 "/" 前缀下时才弹 popup，弹的内容也用焦点窗格的 popup_state。
    let (input_snapshot, popup_open) = {
        let st = app.focused_state();
        (st.input.clone(), st.popup_open)
    };
    if !popup_open {
        return;
    }
    let filtered = filter_meta(&input_snapshot);
    if filtered.is_empty() {
        return;
    }
    // 宽度加宽（内容不截断），高度克制（不遮挡太多窗格内容）。
    // 宽度取终端 85%，最少 74；高度最多 12 行（含边框），够看常用命令。
    let height = (filtered.len() as u16 + 2).min(12);
    let width = 74.max((frame.area().width as f32 * 0.85) as u16);
    let width = width.min(input_area.width.saturating_sub(2));
    let area = Rect {
        x: input_area.x + 1,
        y: input_area.y.saturating_sub(height),
        width,
        height,
    };
    // Each item: cyber 图标 + 命令名 + args-hint + help。
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|m| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", m.icon),
                    Style::default().fg(theme::accent_dim()),
                ),
                Span::styled(
                    format!("{:11} ", m.name),
                    Style::default().fg(theme::accent()),
                ),
                Span::styled(format!("{:18} ", m.args_hint), theme::muted()),
                Span::styled(m.help, theme::faint()),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::surface2()))
                .title(Span::styled(" menu ", theme::muted()))
                .style(theme::input_bg())
                .padding(Padding::horizontal(1)),
        )
        .highlight_style(theme::selected());
    frame.render_widget(Clear, area);
    // render_stateful_widget 需要 &mut ListState，所以这里临时借用焦点窗格状态。
    frame.render_stateful_widget(list, area, &mut app.focused_state_mut().popup_state);
}

/// 渲染视图选择器 popup：在某窗格 tab 正下方画一个小菜单，列出全部 6 个视图。
/// 当前视图高亮；点击或 ↑↓+Enter 选择。把 picker 的可点击行区记录到 hit regions
/// 不必要——click 直接按坐标算（菜单固定从 tab 下方开始，每行高 1）。
fn render_view_picker(frame: &mut ratatui::Frame, app: &mut App) {
    // 先克隆出 picker 状态避免长借用 app（后面还要 render_stateful_widget 借 app）。
    let (pane_id, _) = match app.view_picker.clone() {
        Some(p) => p,
        None => return,
    };
    // 找该窗格的 tab rect，菜单从 tab 正下方开始。
    let tab_rect = match app.view_tab_rect.get(&pane_id) {
        Some(r) => *r,
        None => return,
    };
    let cur_view = app
        .pane_tree
        .leaves()
        .iter()
        .find(|(id, _)| *id == pane_id)
        .map(|(_, v)| *v);

    let count = panes::PaneView::ALL.len();
    let height = (count as u16 + 2).min(10); // +2 边框，封顶 10 行
    let width = 14u16; // 最长 label "sessions"=8 + 边框 + padding
    let area = Rect {
        x: tab_rect.x,
        y: tab_rect.y.saturating_add(1), // tab 下一行
        width,
        height,
    };
    frame.render_widget(Clear, area);
    let items: Vec<ListItem> = panes::PaneView::ALL
        .iter()
        .map(|v| {
            let is_cur = cur_view == Some(*v);
            let mark = if is_cur { "● " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(mark, Style::default().fg(theme::accent())),
                Span::styled(v.label(), if is_cur { theme::brand() } else { theme::text() }),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::surface2()))
                .style(theme::input_bg())
                .padding(Padding::horizontal(1))
                .title(Span::styled(" view ", theme::muted())),
        )
        .highlight_style(theme::selected());
    if let Some((_, state)) = app.view_picker.as_mut() {
        frame.render_stateful_widget(list, area, state);
    }
}

fn render_overlay(frame: &mut ratatui::Frame, app: &mut App, full: Rect) {
    // overlay 限制在焦点窗格内：直接覆盖窗格的边框内容区（各方向缩进 1，贴边框内侧）。
    // 不再全屏遮挡——分屏下其他窗格保持可见。窗格太小时保护性 clamp。
    let area = Rect {
        x: full.x + 1,
        y: full.y + 1,
        width: full.width.saturating_sub(2),
        height: full.height.saturating_sub(2).max(3), // 至少留 3 行画标题+内容+底
    };
    frame.render_widget(Clear, area);
    // overlay 统一圆角风格：圆角边框 + surface2 退让色 + input_bg 底 + padding。
    let make_block = |title: &str| {
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::accent_dim()))
            .style(theme::input_bg())
            .padding(Padding::new(1, 1, 0, 1))
            .title(Span::styled(format!(" {title} "), theme::brand()))
            .title_bottom(Span::styled(" q/Esc ", theme::muted()))
    };
    let cur_id = app.current_session().map(|s| s.id.clone());
    match &mut app.overlay {
        Overlay::None => {}
        Overlay::Sessions(state) => {
            // 先画 block（标题+边框），拿 inner 区域逐行渲染 session。
            // 手动逐行而非 List widget：List 的滚动偏移不可外部读取，
            // 导致 click 坐标映射失效。手动渲染每行 hit region 精确记录。
            let block = make_block("beacons  ↑/↓ select · Enter · click pick");
            frame.render_widget(Clear, area);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let cur = state.selected().unwrap_or(0);
            // 记录每行的 hit region，供 click 精确命中。
            let mut row_rects: Vec<Rect> = Vec::new();
            for (i, s) in app.sessions.iter().enumerate() {
                let row_y = inner.y + i as u16;
                if row_y >= inner.y + inner.height {
                    break; // 超出 inner 截断（不滚动，简单可靠）
                }
                let row_rect = Rect {
                    x: inner.x,
                    y: row_y,
                    width: inner.width,
                    height: 1,
                };
                row_rects.push(row_rect);
                let is_cur = cur_id.as_deref() == Some(&s.id);
                let is_selected = i == cur;
                let mark = if is_cur { "▸ " } else { "  " };
                let admin = if s.is_admin == 1 { " ⚡" } else { "" };
                let base_style = if is_selected {
                    theme::selected()
                } else {
                    theme::text()
                };
                let line = Line::from(vec![
                    Span::styled(mark, Style::default().fg(theme::mauve())),
                    Span::styled(
                        format!("{:10} ", short(&s.id)),
                        Style::default().fg(theme::accent()),
                    ),
                    Span::styled(format!("{:14} ", s.hostname), base_style),
                    Span::styled(format!("{:14} ", s.username), base_style),
                    Span::styled(format!("{:5} ", arch_str(s.arch)), theme::muted()),
                    Span::styled(format!("#{:<6} ", s.beacon_id), theme::muted()),
                    Span::styled(
                        format!("{:4}{} ", "", admin),
                        Style::default().fg(theme::warn()),
                    ),
                    Span::styled(s.os.clone(), theme::faint()),
                ]);
                frame.render_widget(Paragraph::new(line), row_rect);
            }
            app.session_row_rects = row_rects;
        }
        Overlay::Files(rows) => {
            let header = ["NAME", "SIZE", "TYPE", "MODIFIED"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|f| {
                    vec![
                        f.name.clone(),
                        f.size.to_string(),
                        if f.is_dir { "dir" } else { "file" }.into(),
                        f.modified.clone(),
                    ]
                })
                .collect();
            render_table(frame, area, &header, &body, "files");
        }
        Overlay::Procs(rows) => {
            let header = ["PID", "PPID", "USER", "NAME"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|p| {
                    vec![
                        p.pid.to_string(),
                        p.ppid.to_string(),
                        p.user.clone(),
                        p.name.clone(),
                    ]
                })
                .collect();
            render_table(frame, area, &header, &body, "processes");
        }
        Overlay::Creds(rows) => {
            let header = ["SOURCE", "PRINCIPAL", "KIND", "SECRET"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|c| {
                    vec![
                        c.source.clone(),
                        c.principal.clone(),
                        c.kind.label().into(),
                        input::mask(&c.secret),
                    ]
                })
                .collect();
            render_table(frame, area, &header, &body, "credentials");
        }
        Overlay::Audit(rows) => {
            let header = ["#", "TIME", "OPERATOR", "ACTION"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|a| {
                    // detail (JSON) goes into the 4th col truncated; target into 3rd.
                    let target = if a.target.is_empty() {
                        a.operator.clone()
                    } else {
                        format!("{} » {}", a.operator, a.target)
                    };
                    vec![a.seq.to_string(), format_ts(a.ts), target, a.action.clone()]
                })
                .collect();
            render_table(frame, area, &header, &body, "audit log");
        }
        Overlay::Image(path, bytes) => {
            let header = ["PATH", "BYTES"];
            let body = vec![vec![path.clone(), bytes.to_string()]];
            render_table(frame, area, &header, &body, "screenshot");
        }
        Overlay::Profile {
            loaded,
            http_get_uri,
            http_post_uri,
            useragent,
        } => {
            let header = ["FIELD", "VALUE"];
            let body = vec![
                vec!["loaded".into(), loaded.to_string()],
                vec!["http_get".into(), http_get_uri.clone()],
                vec!["http_post".into(), http_post_uri.clone()],
                vec!["useragent".into(), useragent.clone()],
            ];
            render_table(frame, area, &header, &body, "c2 profile");
        }
        Overlay::AuditVerify { ok, broken_at } => {
            let header = ["STATUS", "BROKEN_AT"];
            let status = if *ok { "OK" } else { "BROKEN" };
            let broken = broken_at
                .as_ref()
                .map(|b| b.to_string())
                .unwrap_or_else(|| "-".into());
            let body = vec![vec![status.into(), broken]];
            render_table(frame, area, &header, &body, "audit chain");
        }
        Overlay::SessionDetail(id_ref) => {
            // 本地数据 overlay：每帧从 app.sessions 实时查找（所以 pending/age 是活的）。
            // 这是 ja3/ja4/pid/age_secs/pending 的唯一展示入口——它们在 SessionView
            // 里一直有，但 Sessions 行列表和状态栏都放不下。
            //
            // match &mut app.overlay 使 overlay 的可变借用贯穿整个 arm；直接读
            // app.sessions / sessions_meta / age_for 会与之冲突。先把 id clone 成
            // 所有权值，可变借用随即结束，后续对 app 的不可变借用即可成立。
            let id = id_ref.clone();
            match app.sessions.iter().find(|s| s.id == id) {
                Some(s) => {
                    let meta = app.sessions_meta.get(&id);
                    let age = app.age_for(&id);
                    let rows = build_session_detail_rows(s, &meta, age);
                    render_kv(frame, area, &rows, "session detail");
                }
                None => {
                    let block = Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(theme::accent_dim()))
                        .style(theme::input_bg())
                        .title(Span::styled(" session detail ", theme::brand()))
                        .title_bottom(Span::styled(" q/Esc ", theme::muted()));
                    let para = Paragraph::new(" session gone").style(theme::muted());
                    frame.render_widget(block, area);
                    frame.render_widget(para, area);
                }
            }
        }
        Overlay::Tasks(rows) => {
            let header = ["TASK_ID", "TYPE", "ARG", "DETAIL"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|t| {
                    let ty = t
                        .command
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string();
                    vec![
                        t.task_id.to_string(),
                        ty,
                        task_arg(&t.command),
                        task_detail(&t.command),
                    ]
                })
                .collect();
            render_table(frame, area, &header, &body, "queued tasks");
        }
    }
}

/// Format a Unix-seconds timestamp as a short local-ish string for the audit
/// table. Falls back to the raw seconds if the system clock can't represent it.
fn format_ts(ts: u64) -> String {
    // Use a simple h/m/s over the day-of-epoch; avoid pulling chrono for a table cell.
    let secs = ts;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    format!("d{days} {h:02}:{m:02}:{s:02}")
}

fn render_table(
    frame: &mut ratatui::Frame,
    area: Rect,
    header: &[&str],
    rows: &[Vec<String>],
    title: &str,
) {
    use ratatui::widgets::{Cell, Row, Table};
    let header_row = Row::new(header.iter().map(|h| Cell::from(*h)))
        .style(
            Style::default()
                .fg(theme::muted_color())
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1); // header 和数据行间留 1 行空隙，呼吸感
    let data_rows: Vec<Row> = rows
        .iter()
        .map(|r| Row::new(r.iter().cloned().map(|c| Cell::new(c).style(theme::text()))))
        .collect();
    // 按列数挑宽度：4 列用原比例（32/14/18/36），2 列用 22/78，其余均分。
    let widths: Vec<Constraint> = match header.len() {
        4 => vec![
            Constraint::Percentage(32),
            Constraint::Percentage(14),
            Constraint::Percentage(18),
            Constraint::Percentage(36),
        ],
        2 => vec![Constraint::Percentage(22), Constraint::Percentage(78)],
        _ => (0..header.len())
            .map(|_| Constraint::Percentage((100 / header.len()) as u16))
            .collect(),
    };
    // 统一圆角风格：圆角 + accent_dim 边框 + padding，与 overlay make_block 一致。
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::accent_dim()))
        .style(theme::input_bg())
        .padding(Padding::new(1, 1, 0, 1))
        .title(Span::styled(format!(" {title} "), theme::brand()))
        .title_bottom(Span::styled(" q/Esc ", theme::muted()));
    let table = Table::new(data_rows, widths)
        .header(header_row)
        .highlight_style(theme::selected())
        .block(block);
    frame.render_widget(table, area);
}

/// 2 列 key/value 表（左窄右宽），用于 `/info` 会话详情。
/// 与 4 列的 [`render_table`] 同样的 themed 外观，仅列数/宽度不同。
fn render_kv(frame: &mut ratatui::Frame, area: Rect, rows: &[(String, String)], title: &str) {
    use ratatui::widgets::{Cell, Row, Table};
    let header_row = Row::new(["KEY", "VALUE"].iter().map(|h| Cell::from(*h))).style(
        Style::default()
            .fg(theme::muted_color())
            .add_modifier(Modifier::BOLD),
    );
    let data_rows: Vec<Row> = rows
        .iter()
        .map(|(k, v)| {
            Row::new(vec![
                Cell::new(k.as_str()).style(theme::muted()),
                Cell::new(v.as_str()).style(theme::text()),
            ])
        })
        .collect();
    let widths = [Constraint::Percentage(22), Constraint::Percentage(78)];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::accent_dim()))
        .style(theme::input_bg())
        .padding(Padding::new(1, 1, 0, 1))
        .title(Span::styled(format!(" {title} "), theme::brand()))
        .title_bottom(Span::styled(" q/Esc ", theme::muted()));
    let table = Table::new(data_rows, widths)
        .header(header_row)
        .highlight_style(theme::selected())
        .block(block);
    frame.render_widget(table, area);
}

/// 构建 `/info` 详情表的数据行：SessionView 全字段 + 本地 meta（alias/tags/star/notes）。
/// `age` 由调用方客户端推算传入（`app.age_for(id)`），故每帧都是活的。
fn build_session_detail_rows(
    s: &SessionView,
    meta: &super::session_meta::SessionMeta,
    age: u64,
) -> Vec<(String, String)> {
    let ja3 = s.ja3.clone().unwrap_or_else(|| "-".into());
    let ja4 = s.ja4.clone().unwrap_or_else(|| "-".into());
    let alias = meta.alias.clone().unwrap_or_else(|| "-".into());
    let tags = if meta.tags.is_empty() {
        "-".into()
    } else {
        meta.tags.join(", ")
    };
    let star = if meta.favorite { "★ favorite" } else { "-" };
    let notes = meta.notes.clone().unwrap_or_else(|| "-".into());
    vec![
        ("id".into(), s.id.clone()),
        ("beacon_id".into(), s.beacon_id.to_string()),
        ("hostname".into(), s.hostname.clone()),
        ("username".into(), s.username.clone()),
        ("os".into(), s.os.clone()),
        ("arch".into(), arch_str(s.arch).to_string()),
        ("pid".into(), s.pid.to_string()),
        (
            "admin".into(),
            if s.is_admin == 1 {
                "yes ⚡".into()
            } else {
                "no".into()
            },
        ),
        ("pending".into(), format!("{} queued", s.pending)),
        ("age".into(), fmt_age(age)),
        ("ja3".into(), ja3),
        ("ja4".into(), ja4),
        ("alias".into(), alias),
        ("tags".into(), tags),
        ("star".into(), star.into()),
        ("notes".into(), notes),
    ]
}

/// 提取排队任务的主要参数（一个短摘要），用于 `/tasks` 表的 ARG 列。
/// 按常见 command type 取最显眼的字段；不认识的 type 显示 "-"。
fn task_arg(cmd: &serde_json::Value) -> String {
    let ty = match cmd.get("type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return "-".into(),
    };
    let str_field = |k: &str| cmd.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    match ty {
        "shell" => str_field("args"),
        "bof" => str_field("name"),
        "upload" => str_field("name"),
        "download" => str_field("path"),
        "sleep" => cmd.get("seconds").map(|s| s.to_string()),
        "fileop" => str_field("path"),
        "connect" | "portscan" => str_field("host"),
        "screenshot" => cmd.get("monitor").map(|m| format!("mon:{m}")),
        "env" => str_field("name"),
        "stealtoken" => cmd.get("pid").map(|p| format!("pid:{p}")),
        "maketoken" => str_field("user"),
        _ => None,
    }
    .unwrap_or_else(|| "-".into())
}

/// 提取排队任务的次要详情，用于 `/tasks` 表的 DETAIL 列。
/// 这是 ARG 列装不下的补充信息（端口、jitter、子操作等）。
fn task_detail(cmd: &serde_json::Value) -> String {
    let ty = match cmd.get("type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return "-".into(),
    };
    let str_field = |k: &str| cmd.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    match ty {
        "sleep" => cmd.get("jitter_pct").map(|j| format!("jitter:{j}%")),
        "fileop" => str_field("op"),
        "connect" => cmd.get("port").map(|p| format!("port:{p}")),
        "portscan" => str_field("ports"),
        "bof" => cmd
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|s| !s.is_empty()),
        "net" => str_field("query"),
        "hashdump" => cmd.get("method").map(|m| format!("method:{m}")),
        "keylog" => cmd.get("action").map(|a| format!("action:{a}")),
        "maketoken" => cmd.get("logon_type").map(|lt| format!("logon:{lt}")),
        _ => None,
    }
    .unwrap_or_else(|| "-".into())
}
