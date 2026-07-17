//! Global event log — virtualized list of operator/server activity lines.
//!
//! Reads the crate-global `LOG_LINES` during `draw_walk` (same Makepad
//! `todo`-example pattern as [`super::session_list`]). The DSL template lives
//! in this file's `script_mod!`; the shared `LogLine` row template is also
//! used by [`super::console_list`].

use makepad_widgets::*;

use crate::theme::Palette;
use crate::LOG_LINES;

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*
    use mod.nyx.*

    // ── log row (monospace — it's a tail of operator/session output) ────────
    // Shared by the event log and the per-session console list.
    mod.widgets.LogLine = View{
        width: Fill height: Fit
        padding: Inset{left: Cpad right: Cpad top: 1.0 bottom: 1.0}
        line := Label{
            width: Fill
            text: ""
            draw_text.color: Csecond
            draw_text.text_style: theme.font_code{font_size: 12}
        }
    }
    mod.widgets.LogListBase = #(LogList::register_widget(vm))
    mod.widgets.LogList = set_type_default() do mod.widgets.LogListBase{
        width: Fill height: Fill
        list := PortalList{
            width: Fill height: Fill
            spacing: 0.0
            scroll_bar: ScrollBar{}
            Item := CachedView{mod.widgets.LogLine{}}
        }
    }
}

// ── LogList widget (virtualized, reads LOG_LINES global) ────────────────────

#[derive(Script, ScriptHook, Widget)]
pub struct LogList {
    #[deref]
    view: View,
}

impl Widget for LogList {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let lines_guard = LOG_LINES.read().unwrap_or_else(|e| e.into_inner());
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                list.set_item_range(cx, 0, lines_guard.len());
                while let Some(item_id) = list.next_visible_item(cx) {
                    let Some(line) = lines_guard.get(item_id) else {
                        continue;
                    };
                    let item = list.item(cx, item_id, id!(Item));

                    // Repaint the log row from the Palette source.
                    let p = Palette::current();
                    let mut row_item = item.clone();
                    script_apply_eval!(cx, row_item, {
                        draw_bg +: { color: #(p.row), color_hover: #(p.rowhov) }
                    });
                    let mut line_lbl = item.label(cx, ids!(line));
                    script_apply_eval!(cx, line_lbl, { draw_text +: { color: #(p.second) } });
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
