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
use crate::types::{arch_str, SessionView};

use super::input::{self, filter_meta};
use super::panes;
use super::{fmt_age, short, App, Overlay};

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
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    render_statusbar(frame, app, chunks[0]);
    // 窗格树区域：递归渲染每个叶。
    let pane_area = chunks[1];
    let layouts = app.pane_tree.clone().layout(pane_area);
    for (id, rect) in &layouts {
        let is_focused = *id == app.focused_pane;
        let view = app
            .pane_tree
            .leaves()
            .iter()
            .find(|(lid, _)| lid == id)
            .map(|(_, v)| *v);
        render_pane(
            frame,
            app,
            *id,
            *rect,
            is_focused,
            view.unwrap_or(panes::PaneView::Console),
        );
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
fn render_pane(
    frame: &mut ratatui::Frame,
    app: &mut App,
    _id: usize,
    area: Rect,
    focused: bool,
    view: panes::PaneView,
) {
    // 焦点窗格用 Accent 边框，非焦点用 Faint。
    let border = if focused { theme::ACCENT } else { theme::FAINT };
    let title = format!(" {} ", view.label());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            title,
            if focused {
                theme::brand()
            } else {
                theme::muted()
            },
        ))
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
            // Render the SAME parsed file listing the fullscreen overlay uses
            // (cached in App::files_view), instead of a hardcoded placeholder.
            // Empty → show the hint so the operator knows to run /ls.
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
fn render_stream_content(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let height = area.height as usize;
    let total = app.stream.len();
    let end = total.saturating_sub(app.stream_offset);
    let start = end.saturating_sub(height);
    let visible = &app.stream[start..end.min(total)];
    let lines: Vec<Line> = visible
        .iter()
        .map(|l| {
            Line::from(vec![
                Span::styled("▎ ", theme::level_marker(l.level)),
                Span::styled(l.text.clone(), theme::level(l.level)),
            ])
        })
        .collect();
    let para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// 在窗格里渲染 session 列表（只读预览）。
fn render_sessions_in_pane(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    if app.sessions.is_empty() {
        let para = Paragraph::new("(no beacons — waiting for sessions)").style(theme::muted());
        frame.render_widget(para, area);
        return;
    }
    let lines: Vec<Line> = app
        .sessions
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mark = if app.selected == Some(i) {
                "▸ "
            } else {
                "  "
            };
            let m = app.sessions_meta.get(&s.id);
            let star = if m.favorite { "★" } else { " " };
            let alias = m.alias.as_deref().unwrap_or("");
            Line::from(vec![
                Span::styled(mark, Style::default().fg(theme::MAUVE)),
                Span::styled(
                    format!("{:8} ", short(&s.id)),
                    Style::default().fg(theme::ACCENT),
                ),
                Span::styled(format!("{:14} ", s.hostname), theme::text()),
                Span::styled(format!("{:12} ", s.username), theme::text()),
                Span::styled(star, Style::default().fg(theme::WARN)),
                Span::styled(format!(" {alias}"), theme::muted()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
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
            .fg(theme::MAUVE)
            .add_modifier(Modifier::BOLD),
    );
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

/// Dimmed single-line hint shown when a pane view has no data yet.
fn hint(frame: &mut ratatui::Frame, area: Rect, msg: &str) {
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
        Some(s) => {
            // user@host · <id> · pend:N(仅当>0) · <age>。age 每帧由 age_for() 推算，
            // 每秒自然推进；不触发 session 全表重绘（status bar 单行重绘）。
            let mut buf = format!("{}@{} · {}", s.username, s.hostname, short(&s.id));
            if s.pending > 0 {
                buf.push_str(&format!(" · pend:{}", s.pending));
            }
            buf.push_str(&format!(" · {}", fmt_age(app.age_for(&s.id))));
            buf
        }
        None => "no beacon".to_string(),
    };
    let line = Line::from(vec![
        Span::styled(" nyx ", theme::brand()),
        Span::styled(" ", theme::muted()),
        Span::styled(dot, dot_style),
        Span::styled(format!(" {label}"), theme::muted()),
        Span::styled("  ", theme::muted()),
        Span::styled(
            format!("{} ", app.sessions.len()),
            Style::default()
                .fg(theme::MAUVE)
                .add_modifier(Modifier::BOLD),
        ),
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
        .title(Span::styled(
            " type a command · / for menu ",
            theme::muted(),
        ));
    frame.render_widget(Paragraph::new("").style(theme::input_bg()), area);
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
                Span::styled(
                    format!("{:11} ", m.name),
                    Style::default().fg(theme::ACCENT),
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
                    let mark = if app.selected == Some(i) {
                        "▸ "
                    } else {
                        "  "
                    };
                    let admin = if s.is_admin == 1 { " ⚡" } else { "" };
                    Line::from(vec![
                        Span::styled(mark, Style::default().fg(theme::MAUVE)),
                        Span::styled(
                            format!("{:10} ", short(&s.id)),
                            Style::default().fg(theme::ACCENT),
                        ),
                        Span::styled(format!("{:14} ", s.hostname), theme::text()),
                        Span::styled(format!("{:14} ", s.username), theme::text()),
                        Span::styled(format!("{:5} ", arch_str(s.arch)), theme::muted()),
                        Span::styled(format!("#{:<6} ", s.beacon_id), theme::muted()),
                        Span::styled(
                            format!("{:4}{} ", "", admin),
                            Style::default().fg(theme::WARN),
                        ),
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
                        .border_style(theme::faint())
                        .style(theme::header_bg())
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
                .fg(theme::MAUVE)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(0);
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

/// 2 列 key/value 表（左窄右宽），用于 `/info` 会话详情。
/// 与 4 列的 [`render_table`] 同样的 themed 外观，仅列数/宽度不同。
fn render_kv(frame: &mut ratatui::Frame, area: Rect, rows: &[(String, String)], title: &str) {
    use ratatui::widgets::{Cell, Row, Table};
    let header_row = Row::new(["KEY", "VALUE"].iter().map(|h| Cell::from(*h))).style(
        Style::default()
            .fg(theme::MAUVE)
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
