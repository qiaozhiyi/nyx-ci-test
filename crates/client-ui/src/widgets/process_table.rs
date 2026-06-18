//! Pure display widget for the remote `ps` result.
//!
//! Renders the virtualized process list of the currently selected beacon
//! (PID / PPID / name / user / arch columns). Rows are read from the
//! file-local [`PROCS`] global, which an external updater (the bridge)
//! populates off the UI thread.
//!
//! This widget is display-only: it does not own selection state nor trigger
//! process-injection. The integrator wires row selection to G3 action buttons
//! (inject / migrate / kill). `draw_walk` follows the exact [`SessionList`]
//! pattern.

use makepad_widgets::*;
use std::sync::{LazyLock, RwLock};

/// One remote process, as reported by the beacon's `ps` task.
#[derive(Clone, Debug)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub user: String,
    /// 0 = x64, 1 = x86, 2 = arm64 (anything else → "?").
    pub arch: u8,
}

/// Shared process list. Replace the whole `Vec` on each `ps` refresh.
pub static PROCS: LazyLock<RwLock<Vec<ProcEntry>>> = LazyLock::new(|| RwLock::new(Vec::new()));

/// Map the wire arch byte to a human label for the table cell.
pub fn arch_name(a: u8) -> &'static str {
    match a {
        0 => "x64",
        1 => "x86",
        2 => "arm64",
        _ => "?",
    }
}

// ── ProcessTable widget ──────────────────────────────────────────────────────

#[derive(Script, ScriptHook, Widget)]
pub struct ProcessTable {
    #[deref]
    view: View,
}

impl Widget for ProcessTable {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let procs = PROCS.read().unwrap().clone();
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if procs.is_empty() {
                    list.set_item_range(cx, 0, 1);
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let item = list.item(cx, item_id, id!(Empty));
                        item.draw_all_unscoped(cx);
                    }
                } else {
                    list.set_item_range(cx, 0, procs.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(p) = procs.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));
                        item.label(cx, ids!(pid)).set_text(cx, &p.pid.to_string());
                        item.label(cx, ids!(ppid)).set_text(cx, &p.ppid.to_string());
                        item.label(cx, ids!(name)).set_text(cx, &p.name);
                        item.label(cx, ids!(user)).set_text(cx, &p.user);
                        item.label(cx, ids!(arch)).set_text(cx, arch_name(p.arch));
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

#[cfg(test)]
mod tests {
    use super::arch_name;

    #[test]
    fn known_arch_labels() {
        assert_eq!(arch_name(0), "x64");
        assert_eq!(arch_name(1), "x86");
        assert_eq!(arch_name(2), "arm64");
    }

    #[test]
    fn unknown_arch_falls_back() {
        assert_eq!(arch_name(3), "?");
        assert_eq!(arch_name(255), "?");
    }
}
