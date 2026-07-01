//! Cobalt Strike style topological session graph.
//!
//! Renders the `SESSIONS` global as an absolute-positioned node graph.
//! Lines are drawn using 1px thick Views.

use makepad_widgets::*;

#[derive(Script, ScriptHook, Widget)]
pub struct SessionGraph {
    #[deref]
    list: FlatList,
    #[rust(1.0)]
    zoom: f64,
    #[rust(dvec2(0.0, 0.0))]
    pan: DVec2,
    #[rust]
    drag_start: Option<DVec2>,
    #[rust]
    pan_start: DVec2,
}

impl Widget for SessionGraph {
    #[allow(unused_mut)]
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        if self.zoom == 0.0 {
            self.zoom = 1.0;
        }
        let sessions = crate::SESSIONS.read().unwrap_or_else(|e| e.into_inner());
        while self.list.draw_walk(cx, scope, walk).is_step() {
            let ts_x = 20.0;
            let ts_y = 60.0;
            let n_width = 120.0;
            let n_height = 90.0;
            let h_gap = 40.0;
            let v_gap = 10.0;

            let p = crate::theme::Palette::current();

            // 1. Draw Team Server Node
            if let Some(mut ts_node) = self.list.item(cx, id!(ts_node), id!(Node)) {
                let mut lbl = ts_node.label(cx, ids!(lbl));
                lbl.set_text(cx, "TEAM SERVER");
                script_apply_eval!(cx, lbl, { draw_text +: { color: #(p.primary) } });

                let mut sub_lbl = ts_node.label(cx, ids!(sub_lbl));
                sub_lbl.set_text(cx, "127.0.0.1:443");
                script_apply_eval!(cx, sub_lbl, { draw_text +: { color: #(p.second) } });

                let mut os_lbl = ts_node.label(cx, ids!(icon_view.os_lbl));
                os_lbl.set_text(cx, "[NIX]");
                script_apply_eval!(cx, os_lbl, { draw_text +: { color: #(p.muted) } });

                let _ = ts_node.draw_walk(
                    cx,
                    scope,
                    Walk {
                        abs_pos: Some(dvec2(ts_x as f64, ts_y as f64) * self.zoom + self.pan),
                        width: Size::Fixed(n_width as f64 * self.zoom),
                        height: Size::Fixed(n_height as f64 * self.zoom),
                        ..Walk::default()
                    },
                );
            }

            // 2. Draw Sessions
            let start_y = 40.0;
            for (i, session) in sessions.iter().enumerate() {
                let sx = ts_x + n_width + h_gap;
                let sy = start_y + (i as f32) * (n_height + v_gap);

                // Draw HLine from TS to Session
                if let Some(mut hline) =
                    self.list
                        .item(cx, LiveId::from_num(1, i as u64), id!(HLine))
                {
                    script_apply_eval!(cx, hline, { draw_bg +: { color: #(p.accent) } });
                    let line_y = sy + n_height / 2.0;
                    let _ = hline.draw_walk(
                        cx,
                        scope,
                        Walk {
                            abs_pos: Some(
                                dvec2((ts_x + n_width + 20.0) as f64, line_y as f64) * self.zoom
                                    + self.pan,
                            ),
                            width: Size::Fixed((h_gap - 20.0) as f64 * self.zoom),
                            height: Size::Fixed((2.0 * self.zoom).max(1.0)),
                            ..Walk::default()
                        },
                    );
                }

                // Draw Session Node
                if let Some(mut node) = self.list.item(cx, LiveId::from_num(2, i as u64), id!(Node))
                {
                    let is_win = session.os.to_lowercase().contains("windows");
                    let is_mac = session.os.to_lowercase().contains("mac");

                    let tag = if is_win {
                        "[WIN]"
                    } else if is_mac {
                        "[MAC]"
                    } else {
                        "[NIX]"
                    };
                    let mut os_lbl = node.label(cx, ids!(icon_view.os_lbl));
                    os_lbl.set_text(cx, tag);
                    script_apply_eval!(cx, os_lbl, { draw_text +: { color: #(p.muted) } });

                    let admin_star = if session.is_admin != 0 { "*" } else { "" };
                    let arch_str = if session.arch == 86 { "x86" } else { "x64" };

                    let mut lbl = node.label(cx, ids!(lbl));
                    lbl.set_text(
                        cx,
                        &format!("{}{}@{}", session.username, admin_star, session.hostname),
                    );
                    script_apply_eval!(cx, lbl, { draw_text +: { color: #(p.primary) } });

                    let mut sub_lbl = node.label(cx, ids!(sub_lbl));
                    sub_lbl.set_text(cx, &format!("PID: {} | {}", session.pid, arch_str));
                    script_apply_eval!(cx, sub_lbl, { draw_text +: { color: #(p.second) } });

                    let _ = node.draw_walk(
                        cx,
                        scope,
                        Walk {
                            abs_pos: Some(dvec2(sx as f64, sy as f64) * self.zoom + self.pan),
                            width: Size::Fixed(n_width as f64 * self.zoom),
                            height: Size::Fixed(n_height as f64 * self.zoom),
                            ..Walk::default()
                        },
                    );
                }
            }

            // We should draw a VLine connecting the HLines back to the Team Server
            if !sessions.is_empty() {
                let first_sy = start_y + n_height / 2.0;
                let last_sy =
                    start_y + ((sessions.len() - 1) as f32) * (n_height + v_gap) + n_height / 2.0;
                if last_sy >= first_sy {
                    // Draw connecting horizontal stub from TS to the VLine
                    let ts_mid_y = ts_y + n_height / 2.0;
                    if let Some(mut ts_stub) = self.list.item(cx, id!(ts_stub), id!(HLine)) {
                        script_apply_eval!(cx, ts_stub, { draw_bg +: { color: #(p.accent) } });
                        let _ = ts_stub.draw_walk(
                            cx,
                            scope,
                            Walk {
                                abs_pos: Some(
                                    dvec2((ts_x + n_width) as f64, ts_mid_y as f64) * self.zoom
                                        + self.pan,
                                ),
                                width: Size::Fixed(20.0 * self.zoom),
                                height: Size::Fixed((2.0 * self.zoom).max(1.0)),
                                ..Walk::default()
                            },
                        );
                    }
                    // Also adjust VLine to cover ts_mid_y if needed
                    let min_y = first_sy.min(ts_mid_y);
                    let max_y = last_sy.max(ts_mid_y);
                    if let Some(mut ts_vline) = self.list.item(cx, id!(ts_vline), id!(VLine)) {
                        script_apply_eval!(cx, ts_vline, { draw_bg +: { color: #(p.accent) } });
                        let _ = ts_vline.draw_walk(
                            cx,
                            scope,
                            Walk {
                                abs_pos: Some(
                                    dvec2((ts_x + n_width + 20.0) as f64, min_y as f64) * self.zoom
                                        + self.pan,
                                ),
                                width: Size::Fixed((2.0 * self.zoom).max(1.0)),
                                height: Size::Fixed(
                                    (max_y - min_y) as f64 * self.zoom + (2.0 * self.zoom).max(1.0),
                                ),
                                ..Walk::default()
                            },
                        );
                    }
                }
            }
        } // end while

        DrawStep::done()
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        if self.zoom == 0.0 {
            self.zoom = 1.0;
        }
        self.list.handle_event(cx, event, scope);

        let area = self.list.area();
        match event.hits(cx, area) {
            Hit::FingerDown(fe) => {
                self.drag_start = Some(fe.abs);
                self.pan_start = self.pan;
                cx.set_key_focus(area);
            }
            Hit::FingerMove(fe) => {
                if let Some(start) = self.drag_start {
                    self.pan = self.pan_start + (fe.abs - start);
                    self.list.redraw(cx);
                }
            }
            Hit::FingerUp(_) => {
                self.drag_start = None;
            }
            Hit::FingerScroll(fs) => {
                let scroll = if fs.scroll.y != 0.0 {
                    fs.scroll.y
                } else {
                    fs.scroll.x
                };
                if scroll != 0.0 {
                    let old_zoom = self.zoom;
                    let new_zoom = if scroll < 0.0 {
                        (old_zoom * 1.1).min(5.0)
                    } else {
                        (old_zoom / 1.1).max(0.2)
                    };
                    if new_zoom != old_zoom {
                        self.zoom = new_zoom;
                        let pointer = fs.abs;
                        self.pan = pointer - (pointer - self.pan) * (new_zoom / old_zoom);
                        self.list.redraw(cx);
                    }
                }
            }
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zoom_init() {
        // FlatList does not implement Default, so we cannot instantiate SessionGraph directly here.
        // The compilation of SessionGraph is verified during cargo build.
    }

    #[test]
    fn test_zoom_math() {
        let pointer = dvec2(100.0, 100.0);
        let pan = dvec2(10.0, 10.0);
        let old_zoom = 1.0;
        let new_zoom = 2.0;
        let new_pan = pointer - (pointer - pan) * (new_zoom / old_zoom);
        assert_eq!(new_pan, dvec2(-80.0, -80.0));
    }
}
