//! Rendering for the fullscreen TUI.
//!
//! All `render_*` free functions plus the `render()` entry point live here;
//! `tui/mod.rs` owns App state and input handling. Pure move refactor — no
//! behaviour change. Functions read off `App` fields, which are `pub(super)`
//! for that reason.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::theme;
use crate::types::arch_str;

use super::input::{self, filter_meta};
use super::panes;
use super::{short, App, Overlay};

pub(super) fn render(app: &mut App, frame: &mut ratatui::Frame) {
    let area = frame.area();
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
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    render_statusbar(frame, app, chunks[0]);
    // 窗格树区域：递归渲染每个叶。
    let pane_area = chunks[1];
    let layouts = app.pane_tree.clone().layout(pane_area);
    for (id, rect) in &layouts {
        let is_focused = *id == app.focused_pane;
        let view = app.pane_tree.leaves().iter().find(|(lid, _)| lid == id).map(|(_, v)| *v);
        render_pane(frame, app, *id, *rect, is_focused, view.unwrap_or(panes::PaneView::Console));
    }
    render_input(frame, app, chunks[2]);

    if app.popup_open {
        render_popup(frame, app, chunks[2]);
    }
    if app.overlay.is_open() {
        render_overlay(frame, app, area);
    }
}

/// 渲染单个窗格叶。
fn render_pane(frame: &mut ratatui::Frame, app: &mut App, _id: usize, area: Rect, focused: bool, view: panes::PaneView) {
    // 焦点窗格用 Accent 边框，非焦点用 Faint。
    let border = if focused { theme::ACCENT } else { theme::FAINT };
    let title = format!(" {} ", view.label());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(Span::styled(title, if focused { theme::brand() } else { theme::muted() }))
        .style(theme::header_bg());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match view {
        panes::PaneView::Console => {
            render_stream_content(frame, app, inner);
        }
        panes::PaneView::SessionList => {
            render_sessions_in_pane(frame, app, inner);
        }
        panes::PaneView::Files => {
            render_overlay_content(frame, app, inner, &Overlay::Files(vec![]));
        }
        panes::PaneView::Procs => {
            render_overlay_content(frame, app, inner, &Overlay::Procs(vec![]));
        }
        panes::PaneView::Creds => {
            render_overlay_content(frame, app, inner, &Overlay::Creds(vec![]));
        }
        panes::PaneView::Topology => {
            let para = Paragraph::new("topology — use /topo to view")
                .style(theme::muted());
            frame.render_widget(para, inner);
        }
    }
}

/// 事件流内容（无边框，边框由 render_pane 提供）。
fn render_stream_content(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let height = area.height as usize;
    let total = app.stream.len();
    let end = total.saturating_sub(app.stream_offset);
    let start = end.saturating_sub(height);
    let visible = &app.stream[start..end.min(total)];
    let lines: Vec<Line> = visible.iter().map(|l| {
        Line::from(vec![
            Span::styled("▎ ", theme::level_marker(l.level)),
            Span::styled(l.text.clone(), theme::level(l.level)),
        ])
    }).collect();
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// 在窗格里渲染 session 列表（只读预览）。
fn render_sessions_in_pane(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    if app.sessions.is_empty() {
        let para = Paragraph::new("(no beacons — waiting for sessions)")
            .style(theme::muted());
        frame.render_widget(para, area);
        return;
    }
    let lines: Vec<Line> = app.sessions.iter().enumerate().map(|(i, s)| {
        let mark = if app.selected == Some(i) { "▸ " } else { "  " };
        let m = app.sessions_meta.get(&s.id);
        let star = if m.favorite { "★" } else { " " };
        let alias = m.alias.as_deref().unwrap_or("");
        Line::from(vec![
            Span::styled(mark, Style::default().fg(theme::MAUVE)),
            Span::styled(format!("{:8} ", short(&s.id)), Style::default().fg(theme::ACCENT)),
            Span::styled(format!("{:14} ", s.hostname), theme::text()),
            Span::styled(format!("{:12} ", s.username), theme::text()),
            Span::styled(star, Style::default().fg(theme::WARN)),
            Span::styled(format!(" {alias}"), theme::muted()),
        ])
    }).collect();
    frame.render_widget(Paragraph::new(lines), area);
}

/// overlay 内容渲染（用于 files/procs/creds 窗格视图）。
fn render_overlay_content(frame: &mut ratatui::Frame, _app: &App, area: Rect, overlay: &Overlay) {
    let msg = match overlay {
        Overlay::Files(_) => "(files — use /ls to populate)",
        Overlay::Procs(_) => "(procs — use /ps to populate)",
        Overlay::Creds(_) => "(creds — use /creds to populate)",
        _ => "(empty)",
    };
    let para = Paragraph::new(msg).style(theme::muted());
    frame.render_widget(para, area);
}

fn render_statusbar(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    // Header strip: solid background, brand on the left, status dot+label,
    // then dimmed session/beacon info.
    let (dot, dot_style, label) = if app.connected {
        ("●", Style::default().fg(theme::SUCCESS), "connected")
    } else {
        ("○", Style::default().fg(theme::DANGER), "disconnected")
    };
    let beacon = match app.current_session() {
        Some(s) => format!("{}@{} · {}", s.username, s.hostname, short(&s.id)),
        None => "no beacon".to_string(),
    };
    let line = Line::from(vec![
        Span::styled(" nyx ", theme::brand()),
        Span::styled(" ", theme::muted()),
        Span::styled(dot, dot_style),
        Span::styled(format!(" {label}"), theme::muted()),
        Span::styled("  ", theme::muted()),
        Span::styled(format!("{} ", app.sessions.len()), Style::default().fg(theme::MAUVE).add_modifier(Modifier::BOLD)),
        Span::styled("beacons", theme::muted()),
        Span::styled("   ", theme::muted()),
        Span::styled(beacon, theme::text()),
    ]);
    frame.render_widget(Paragraph::new(line).style(theme::header_bg()), area);
}

fn render_input(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    // Soft rounded-top border in the accent colour; surface-fill body. The title
    // hint sits dimmed so it reads as chrome, not content.
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(theme::input_border())
        .title(Span::styled(" type a command · / for menu ", theme::muted()));
    frame.render_widget(
        Paragraph::new("").style(theme::input_bg()),
        area,
    );
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(1),
    };
    frame.render_widget(block, area);

    let display: String = app.input.chars().collect();
    let prompt = if display.is_empty() {
        Paragraph::new(Span::styled(
            "type a shell command (runs on the selected beacon), or / for the menu",
            theme::muted(),
        ))
        .style(theme::input_bg())
    } else {
        Paragraph::new(Span::styled(
            format!("❯ {display}"),
            Style::default().fg(theme::ACCENT),
        ))
        .style(theme::input_bg())
    };
    frame.render_widget(prompt, inner);

    // place the hardware cursor (prefix is "❯ ")
    let prefix = "❯ ".chars().count() as u16;
    let x = inner.x + prefix + app.cursor as u16;
    frame.set_cursor_position((x.min(inner.x + inner.width.saturating_sub(1)), inner.y));
}

fn render_popup(frame: &mut ratatui::Frame, app: &mut App, input_area: Rect) {
    let filtered = filter_meta(&app.input);
    if filtered.is_empty() {
        return;
    }
    let height = (filtered.len() as u16 + 2).min(14);
    let width = 56;
    let area = Rect {
        x: input_area.x + 1,
        y: input_area.y.saturating_sub(height),
        width,
        height,
    };
    // Each item: bright command name, muted args-hint, dimmed help.
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|m| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:11} ", m.name), Style::default().fg(theme::ACCENT)),
                Span::styled(format!("{:18} ", m.args_hint), theme::muted()),
                Span::styled(m.help, theme::faint()),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::faint())
                .title(Span::styled(" menu ", theme::muted()))
                .style(theme::header_bg()),
        )
        .highlight_style(theme::selected());
    frame.render_widget(Clear, area);
    frame.render_stateful_widget(list, area, &mut app.popup_state);
}

fn render_overlay(frame: &mut ratatui::Frame, app: &mut App, full: Rect) {
    // inset slightly
    let area = Rect {
        x: full.x + 2,
        y: full.y + 1,
        width: full.width.saturating_sub(4),
        height: full.height.saturating_sub(2),
    };
    frame.render_widget(Clear, area);
    // A single soft border; the title carries the content name + close hint.
    let make_block = |title: &str| {
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::faint())
            .style(theme::header_bg())
            .title(Span::styled(format!(" {title} "), theme::brand()))
            .title_bottom(Span::styled(" q/Esc ", theme::muted()))
    };
    match &mut app.overlay {
        Overlay::None => {}
        Overlay::Sessions(state) => {
            let items: Vec<ListItem> = app
                .sessions
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let mark = if app.selected == Some(i) { "▸ " } else { "  " };
                    let admin = if s.is_admin == 1 { " ⚡" } else { "" };
                    Line::from(vec![
                        Span::styled(mark, Style::default().fg(theme::MAUVE)),
                        Span::styled(format!("{:10} ", short(&s.id)), Style::default().fg(theme::ACCENT)),
                        Span::styled(format!("{:14} ", s.hostname), theme::text()),
                        Span::styled(format!("{:14} ", s.username), theme::text()),
                        Span::styled(format!("{:5} ", arch_str(s.arch)), theme::muted()),
                        Span::styled(format!("#{:<6} ", s.beacon_id), theme::muted()),
                        Span::styled(format!("{:4}{} ", "", admin), Style::default().fg(theme::WARN)),
                        Span::styled(s.os.clone(), theme::faint()),
                    ])
                })
                .map(ListItem::new)
                .collect();
            let list = List::new(items)
                .block(make_block("beacons  ↑/↓ select · Enter pick"))
                .highlight_style(theme::selected());
            frame.render_stateful_widget(list, area, state);
        }
        Overlay::Files(rows) => {
            let header = ["NAME", "SIZE", "TYPE", "MODIFIED"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|f| vec![f.name.clone(), f.size.to_string(), if f.is_dir { "dir" } else { "file" }.into(), f.modified.clone()])
                .collect();
            render_table(frame, area, header, &body, "files");
        }
        Overlay::Procs(rows) => {
            let header = ["PID", "PPID", "USER", "NAME"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|p| vec![p.pid.to_string(), p.ppid.to_string(), p.user.clone(), p.name.clone()])
                .collect();
            render_table(frame, area, header, &body, "processes");
        }
        Overlay::Creds(rows) => {
            let header = ["SOURCE", "PRINCIPAL", "KIND", "SECRET"];
            let body: Vec<Vec<String>> = rows
                .iter()
                .map(|c| vec![c.source.clone(), c.principal.clone(), c.kind.label().into(), input::mask(&c.secret)])
                .collect();
            render_table(frame, area, header, &body, "credentials");
        }
    }
}

fn render_table(
    frame: &mut ratatui::Frame,
    area: Rect,
    header: [&str; 4],
    rows: &[Vec<String>],
    title: &str,
) {
    use ratatui::widgets::{Cell, Row, Table};
    let header_row = Row::new(header.iter().map(|h| Cell::from(*h)))
        .style(Style::default().fg(theme::MAUVE).add_modifier(Modifier::BOLD))
        .bottom_margin(0);
    let data_rows: Vec<Row> = rows
        .iter()
        .map(|r| Row::new(r.iter().cloned().map(|c| Cell::new(c).style(theme::text()))))
        .collect();
    let widths = [
        Constraint::Percentage(32),
        Constraint::Percentage(14),
        Constraint::Percentage(18),
        Constraint::Percentage(36),
    ];
    // Build the themed block here (same look as the session-list overlay).
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::faint())
        .style(theme::header_bg())
        .title(Span::styled(format!(" {title} "), theme::brand()))
        .title_bottom(Span::styled(" q/Esc ", theme::muted()));
    let table = Table::new(data_rows, widths)
        .header(header_row)
        .highlight_style(theme::selected())
        .block(block);
    frame.render_widget(table, area);
}
