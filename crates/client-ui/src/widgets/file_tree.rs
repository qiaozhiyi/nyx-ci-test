//! Nyx operator GUI — remote file browser (G2, flat-list).
//!
//! Pure display widget for the flat result of a remote `LS` on a beacon. Each
//! row shows a remote path's name, humanized size, and modified timestamp. The
//! operator selects a row (click → download/upload) but that wiring lives in
//! the integrator's `handle_actions`, not here — this widget only renders.
//!
//! G2 is intentionally a flat list (the beacon's LS returns one directory at a
//! time). Recursive tree expansion and the upload/download action buttons
//! arrive in G3. Rows are read from the [`FILES`] global defined here; the
//! writer (bridge / `handle_signal`) lives outside this file.

use makepad_widgets::*;
use std::sync::{LazyLock, RwLock};

/// One remote filesystem entry returned by a beacon LS.
#[derive(Clone, Debug)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: String,
}

static FILES: LazyLock<RwLock<Vec<FileEntry>>> = LazyLock::new(|| RwLock::new(Vec::new()));

/// Format a byte count with a binary unit (B / KiB / MiB / GiB), one decimal.
pub(crate) fn humanize_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

// ── FileTree widget (virtualized, reads FILES global) ───────────────────────

#[derive(Script, ScriptHook, Widget)]
pub struct FileTree {
    #[deref]
    view: View,
}

impl Widget for FileTree {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let files = FILES.read().unwrap().clone();
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if files.is_empty() {
                    list.set_item_range(cx, 0, 1);
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let item = list.item(cx, item_id, id!(Empty));
                        item.draw_all_unscoped(cx);
                    }
                } else {
                    list.set_item_range(cx, 0, files.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(f) = files.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));
                        item.label(cx, ids!(name)).set_text(cx, &f.name);
                        let size_text = if f.is_dir { "—".to_string() } else { humanize_size(f.size) };
                        item.label(cx, ids!(size)).set_text(cx, &size_text);
                        item.label(cx, ids!(modified)).set_text(cx, &f.modified);
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
    use super::humanize_size;

    #[test]
    fn bytes_under_1024_stay_bytes() {
        assert_eq!(humanize_size(0), "0.0 B");
        assert_eq!(humanize_size(1), "1.0 B");
        assert_eq!(humanize_size(1023), "1023.0 B");
    }

    #[test]
    fn kib_boundary() {
        assert_eq!(humanize_size(1024), "1.0 KiB");
        assert_eq!(humanize_size(1536), "1.5 KiB");
    }

    #[test]
    fn mib_and_gib() {
        assert_eq!(humanize_size(1024 * 1024), "1.0 MiB");
        assert_eq!(humanize_size(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn does_not_exceed_gib_unit() {
        // Past GiB it stays in GiB (no TiB unit defined).
        assert!(humanize_size(u64::MAX).ends_with(" GiB"));
    }
}
