//! Per-beacon interactive console output list.
//!
//! Reads from [`crate::CONSOLE`] keyed by the currently-selected session ID.
//! This is the virtualized list that displays only the output relevant to the
//! selected beacon (as opposed to the global event log which shows all activity).

use makepad_widgets::*;

#[derive(Script, ScriptHook, Widget)]
pub struct ConsoleList {
    #[deref]
    view: View,
}

impl Widget for ConsoleList {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        // Resolve the selected session ID.
        let selected_idx = crate::SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
        let sessions_guard = crate::SESSIONS.read().unwrap_or_else(|e| e.into_inner());
        let session_id: Option<&str> = if selected_idx == usize::MAX {
            None
        } else {
            sessions_guard.get(selected_idx).map(|s| s.id.as_str())
        };
        let console_guard = crate::CONSOLE.read().unwrap_or_else(|e| e.into_inner());
        let empty_lines = Vec::new();
        let lines: &Vec<String> = if let Some(sid) = session_id {
            console_guard.get(sid).unwrap_or(&empty_lines)
        } else {
            &empty_lines
        };

        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                list.set_item_range(cx, 0, lines.len());
                while let Some(item_id) = list.next_visible_item(cx) {
                    let Some(line) = lines.get(item_id) else {
                        continue;
                    };
                    let item = list.item(cx, item_id, id!(Item));
                    let p = crate::theme::Palette::current();
                    let mut row_item = item.clone();
                    script_apply_eval!(cx, row_item, {
                        draw_bg +: { color: #(p.row) }
                    });
                    // Colorize: lines starting with "$" are commands (accent), errors are danger, rest secondary.
                    let text_color = if line.starts_with('$') || line.starts_with("$ ") {
                        p.accent
                    } else if line.starts_with("[error]") || line.starts_with('!') {
                        p.danger
                    } else {
                        p.second
                    };
                    let mut line_lbl = item.label(cx, ids!(line));
                    script_apply_eval!(cx, line_lbl, { draw_text +: { color: #(text_color) } });
                    line_lbl.set_text(cx, line);
                    item.draw_all_unscoped(cx);
                }
            }
        }
        DrawStep::done()
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        self.view.handle_event(cx, event, scope);
    }
}
