//! Session table — virtualized list of connected sessions (the home view).
//!
//! Reads the crate-global `SESSIONS` / `SELECTED_SESSION` during `draw_walk`
//! (the Makepad `todo`-example pattern: the App stuffs bridge snapshots into
//! `LazyLock<RwLock<..>>` globals; the widget reads them per frame). The DSL
//! template lives in this file's own `script_mod!` — the App registers it via
//! `widgets::script_mod` before any view mounts it.

use makepad_widgets::*;

use crate::theme::Palette;
use crate::{SELECTED_SESSION, SESSIONS};

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*
    use mod.nyx.*

    // ── session row (one session) ───────────────────────────────────────────
    // `flow: Overlay` so the transparent full-row `select` Button sits ON TOP
    // of the label row and captures clicks across the whole row. This is the
    // only way click-detection works in Makepad: `items_with_actions` yields a
    // row only when one of its child widgets fired an action, and a plain View
    // of Labels never does. Mirrors the `todo` example's per-row Button.
    //
    // DSL syntax note: 2.0 uses DOT-PATH property access (draw_bg.color) and
    // CONSTRUCTORS (Align{..}, Inset{..}), NOT nested object blocks — the
    // latter pass the macro but crash at runtime with "expected DrawQuad, got
    // object". This was the G3 smoke-test root cause.
    let SessionRow = View{
        width: Fill height: 32
        flow: Overlay
        // show_bg defaults to FALSE on View in this Makepad rev — without this
        // the row's draw_bg (normal/hover/selected colors) is never rasterized.
        show_bg: true
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov

        content := View{
            width: Fill height: Fill
            padding: Inset{left: Cpad right: Cpad}
            flow: Right spacing: Cgap
            align: Align{y: 0.5}
            host := Label{
                width: 160
                text: "hostname"
                draw_text.color: Cprimary
                draw_text.text_style: theme.font_regular{font_size: 13}
            }
            v_line1 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
            user := Label{
                width: 112
                text: "user"
                draw_text.color: Csecond
                draw_text.text_style: theme.font_regular{font_size: 13}
            }
            v_line2 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
            os := Label{
                width: Fill
                text: "os"
                draw_text.color: Cmuted
                draw_text.text_style: theme.font_regular{font_size: 13}
            }
            v_line3 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
            admin := Label{
                width: 56
                text: ""
                draw_text.color: Cdanger
                draw_text.text_style: theme.font_bold{font_size: 12}
            }
            v_line4 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
            pend := Label{
                width: 44
                text: "0"
                draw_text.color: Caccent
                draw_text.text_style: theme.font_code{font_size: 13}
            }
        }
        select := Button{
            width: Fill height: Fill
            text: ""
            draw_bg.color: #x00000000
            draw_bg.color_hover: #x00000000
            draw_bg.color_down: #x00000000
            draw_bg.border_size: 0.0
            draw_text.color: #x00000000
        }
        bottom_line := View {
            show_bg: true
            width: Fill height: 1
            margin: Inset{top: 31.0}
            draw_bg.color: Cborder
        }
    }

    mod.widgets.SessionListBase = #(SessionList::register_widget(vm))
    mod.widgets.SessionList = set_type_default() do mod.widgets.SessionListBase{
        width: Fill height: Fill
        flow: Down
        // Column header — a non-virtualized View pinned above the PortalList
        // so it stays put while rows scroll beneath it. Column widths/gap/pad
        // MIRROR SessionRow.content exactly, so headers line up with the data.
        header := View{
            show_bg: true
            width: Fill height: Fit
            flow: Down
            draw_bg.color: Celev
            h_cols := View{
                width: Fill height: 30
                padding: Inset{left: Cpad right: Cpad}
                flow: Right spacing: Cgap
                align: Align{y: 0.5}
                host_lbl := Label{width: 160 text: "HOST" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                hv_line1 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
                user_lbl := Label{width: 112 text: "USER" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                hv_line2 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
                os_lbl := Label{width: Fill text: "OPERATING SYSTEM" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                hv_line3 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
                priv_lbl := Label{width: 56 text: "PRIV" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                hv_line4 := View{show_bg: true width: 1 height: Fill draw_bg.color: Cborder}
                que_lbl := Label{width: 44 text: "QUE" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
            }
            bottom_border := View{show_bg: true width: Fill height: 1 draw_bg.color: Cborder}
        }
        list := PortalList{
            width: Fill height: Fill
            spacing: 1.0
            scroll_bar: ScrollBar{}
            // Two item templates: Item (normal) and ItemSel (selected, violet
            // bg). draw_walk picks per row. The template SWITCH is the actual
            // invalidation mechanism: CachedView renders its content into a
            // cached texture and PortalList::redraw never flags item draw
            // lists, so mutating colors on a live row leaves the stale texture
            // on screen — swapping templates spawns a fresh widget (empty
            // texture cache) that re-renders. The inner SessionRow is named
            // `row` so draw_walk can repaint its bg from the Palette per frame.
            // CachedWidget caches its child GLOBALLY by the child's key name
            // (cached_widget.rs: template_id = child key). Two templates whose
            // child shares one key therefore resolve to THE SAME singleton
            // instance — `row :=` on both made ItemSel reuse Item's widget and
            // the Crowsel override silently never applied (the real reason the
            // selection tint never painted). Distinct keys = distinct instances.
            Item := CachedView{item_row := SessionRow{draw_bg.color: Crow}}
            ItemSel := CachedView{sel_row := SessionRow{draw_bg.color: Crowsel}}
        }
    }
}

// ── SessionList widget (virtualized, reads SESSIONS global) ─────────────────

#[derive(Script, ScriptHook, Widget)]
pub struct SessionList {
    #[deref]
    view: View,
}

impl Widget for SessionList {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let sessions = SESSIONS.read().unwrap().clone();
        let p = Palette::current();

        let mut header = self.view.view(cx, ids!(header));
        script_apply_eval!(cx, header, {
            draw_bg +: { color: #(p.elev) }
        });

        let mut host_lbl = self.view.label(cx, ids!(header.h_cols.host_lbl));
        script_apply_eval!(cx, host_lbl, { draw_text +: { color: #(p.muted) } });

        let mut user_lbl = self.view.label(cx, ids!(header.h_cols.user_lbl));
        script_apply_eval!(cx, user_lbl, { draw_text +: { color: #(p.muted) } });

        let mut os_lbl = self.view.label(cx, ids!(header.h_cols.os_lbl));
        script_apply_eval!(cx, os_lbl, { draw_text +: { color: #(p.muted) } });

        let mut priv_lbl = self.view.label(cx, ids!(header.h_cols.priv_lbl));
        script_apply_eval!(cx, priv_lbl, { draw_text +: { color: #(p.muted) } });

        let mut que_lbl = self.view.label(cx, ids!(header.h_cols.que_lbl));
        script_apply_eval!(cx, que_lbl, { draw_text +: { color: #(p.muted) } });

        let mut hv_line1 = self.view.view(cx, ids!(header.h_cols.hv_line1));
        script_apply_eval!(cx, hv_line1, { draw_bg +: { color: #(p.border) } });

        let mut hv_line2 = self.view.view(cx, ids!(header.h_cols.hv_line2));
        script_apply_eval!(cx, hv_line2, { draw_bg +: { color: #(p.border) } });

        let mut hv_line3 = self.view.view(cx, ids!(header.h_cols.hv_line3));
        script_apply_eval!(cx, hv_line3, { draw_bg +: { color: #(p.border) } });

        let mut hv_line4 = self.view.view(cx, ids!(header.h_cols.hv_line4));
        script_apply_eval!(cx, hv_line4, { draw_bg +: { color: #(p.border) } });

        let mut bottom_border = self.view.view(cx, ids!(header.bottom_border));
        script_apply_eval!(cx, bottom_border, { draw_bg +: { color: #(p.border) } });

        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if sessions.is_empty() {
                    // Empty list: render zero rows. We deliberately do NOT use
                    // the todo-style `set_item_range(0,1)` + Empty-view trick
                    // here: drawing a single Empty row on first paint (before
                    // the layout pass completes) causes the PortalList to
                    // measure 0 tall, which cascades to a 0x0 window that never
                    // comes onscreen (verified via CGWindowList). The todo
                    // example sidesteps this by pre-populating its list at
                    // startup, so its empty branch never runs on first paint.
                    // The empty-state guidance is a separate overlay the App
                    // toggles (`session_empty_hint` in views/workspace.rs).
                    list.set_item_range(cx, 0, 0);
                } else {
                    let sel = SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
                    list.set_item_range(cx, 0, sessions.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(s) = sessions.get(item_id) else {
                            continue;
                        };
                        // Selected row uses the ItemSel template (violet bg);
                        // others use Item. Verified per-row-id approach.
                        let is_sel = item_id == sel;
                        let item = list.item(
                            cx,
                            item_id,
                            if is_sel {
                                id!(ItemSel)
                            } else {
                                id!(Item)
                            },
                        );

                        // Repaint the row bg from the single Palette source so
                        // the Light/Dark toggle matches apply_theme exactly.
                        // Must target the inner SessionRow (`item_row`/`sel_row`
                        // — distinct cache keys, see the template comment above):
                        // eval applies don't propagate to children, and the
                        // CachedView wrapper's own draw_bg is the texture-sampler
                        // shader, which ignores `color` (the old item.clone()
                        // apply was a silent no-op).
                        let row_color = if is_sel { p.rowsel } else { p.row };
                        let mut row_bg = if is_sel {
                            item.view(cx, ids!(sel_row))
                        } else {
                            item.view(cx, ids!(item_row))
                        };
                        script_apply_eval!(cx, row_bg, {
                            draw_bg +: { color: #(row_color), color_hover: #(p.rowhov) }
                        });

                        // Labels live under `content` (overlay layout).
                        let mut host = item.label(cx, ids!(content.host));
                        script_apply_eval!(cx, host, { draw_text +: { color: #(p.primary) } });
                        host.set_text(cx, &s.hostname);

                        let mut user = item.label(cx, ids!(content.user));
                        script_apply_eval!(cx, user, { draw_text +: { color: #(p.second) } });
                        user.set_text(cx, &s.username);

                        let mut os = item.label(cx, ids!(content.os));
                        script_apply_eval!(cx, os, { draw_text +: { color: #(p.muted) } });
                        os.set_text(cx, &s.os);

                        let mut admin = item.label(cx, ids!(content.admin));
                        script_apply_eval!(cx, admin, { draw_text +: { color: #(p.danger) } });
                        admin.set_text(cx, if s.is_admin != 0 { "ADMIN" } else { "" });

                        let mut pend = item.label(cx, ids!(content.pend));
                        script_apply_eval!(cx, pend, { draw_text +: { color: #(p.accent) } });
                        pend.set_text(cx, &s.pending.to_string());

                        let mut v_line1 = item.view(cx, ids!(content.v_line1));
                        script_apply_eval!(cx, v_line1, { draw_bg +: { color: #(p.border) } });

                        let mut v_line2 = item.view(cx, ids!(content.v_line2));
                        script_apply_eval!(cx, v_line2, { draw_bg +: { color: #(p.border) } });

                        let mut v_line3 = item.view(cx, ids!(content.v_line3));
                        script_apply_eval!(cx, v_line3, { draw_bg +: { color: #(p.border) } });

                        let mut v_line4 = item.view(cx, ids!(content.v_line4));
                        script_apply_eval!(cx, v_line4, { draw_bg +: { color: #(p.border) } });

                        let mut bottom_line = item.view(cx, ids!(bottom_line));
                        script_apply_eval!(cx, bottom_line, { draw_bg +: { color: #(p.border) } });

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
