//! BOF loader panel — Nyx operator GUI (G2).
//!
//! A BOF (Beacon Object File) is an in-implant COFF payload an operator runs on
//! a beacon. This module is a **pure display widget**: it renders the history of
//! previously-run BOFs as a virtualized list (name / status / arg summary) and a
//! centered empty-state when nothing has run yet.
//!
//! It owns no I/O and no event handling beyond delegating to its [`View`]. The
//! data it shows lives in the process-global [`BOFS`] (`LazyLock<RwLock<..>>`,
//! the same idiom Makepad's `todo` example and the in-repo `SessionList` use).
//! The bridge writes entries there off-thread; this widget only reads + redraws.

use makepad_widgets::*;
use std::sync::{LazyLock, RwLock};

// ── shared UI state, read by BofPanel during draw ────────────────────────────

/// Shared BOF history. The App pushes updates from the bridge snapshot here;
/// the widget reads a snapshot during draw. Capped at 1024 rows so a runaway
/// BOF loop can't grow it unbounded.
pub static BOFS: LazyLock<RwLock<Vec<BofEntry>>> = LazyLock::new(|| RwLock::new(Vec::new()));

/// Outcome of a single BOF execution, shown as a per-row status tag.
#[derive(Clone, Debug)]
pub enum BofStatus {
    Pending,
    Done,
    Error,
}

/// One row in the BOF history list. `args` is a pre-formatted summary string.
#[derive(Clone, Debug)]
pub struct BofEntry {
    pub name: String,
    pub args: String,
    pub status: BofStatus,
}

// ── BofPanel widget (virtualized, reads BOFS global) ─────────────────────────

#[derive(Script, ScriptHook, Widget)]
pub struct BofPanel {
    #[deref]
    view: View,
}

impl Widget for BofPanel {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let bofs_guard = BOFS.read().unwrap_or_else(|e| e.into_inner());
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if bofs_guard.is_empty() {
                    list.set_item_range(cx, 0, 0);
                } else {
                    list.set_item_range(cx, 0, bofs_guard.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(b) = bofs_guard.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));

                        // Repaint the row from the single Palette source.
                        let p = crate::theme::Palette::current();
                        let mut row_item = item.clone();
                        script_apply_eval!(cx, row_item, {
                            draw_bg +: { color: #(p.row), color_hover: #(p.rowhov) }
                        });

                        let mut name_lbl = item.label(cx, ids!(name));
                        script_apply_eval!(cx, name_lbl, { draw_text +: { color: #(p.primary) } });
                        name_lbl.set_text(cx, &b.name);

                        // Status carries semantic color: pending=warn, done=success, error=danger.
                        let status_color = match b.status {
                            BofStatus::Pending => p.warn,
                            BofStatus::Done => p.success,
                            BofStatus::Error => p.danger,
                        };
                        let mut status_lbl = item.label(cx, ids!(status));
                        script_apply_eval!(cx, status_lbl, { draw_text +: { color: #(status_color) } });
                        status_lbl.set_text(cx, match b.status {
                            BofStatus::Pending => "pending",
                            BofStatus::Done => "done",
                            BofStatus::Error => "error",
                        });

                        let mut args_lbl = item.label(cx, ids!(args));
                        script_apply_eval!(cx, args_lbl, { draw_text +: { color: #(p.muted) } });
                        args_lbl.set_text(cx, &b.args);
                        item.draw_all_unscoped(cx);
                    }
                }
            }
        }
        DrawStep::done()
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        self.view.handle_event(cx, event, scope);
    }
}
