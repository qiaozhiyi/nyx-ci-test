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
        let bofs = BOFS.read().unwrap().clone();
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if bofs.is_empty() {
                    list.set_item_range(cx, 0, 1);
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let item = list.item(cx, item_id, id!(Empty));
                        item.draw_all_unscoped(cx);
                    }
                } else {
                    list.set_item_range(cx, 0, bofs.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(b) = bofs.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));
                        item.label(cx, ids!(name)).set_text(cx, &b.name);
                        item.label(cx, ids!(status)).set_text(cx, match b.status {
                            BofStatus::Pending => "pending",
                            BofStatus::Done => "done",
                            BofStatus::Error => "error",
                        });
                        item.label(cx, ids!(args)).set_text(cx, &b.args);
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
