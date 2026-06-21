//! Cobalt Strike style topological session graph.
//!
//! Renders the `SESSIONS` global as an absolute-positioned node graph.
//! Lines are drawn using 1px thick Views.

use makepad_widgets::*;

#[derive(Script, ScriptHook, Widget)]
pub struct SessionGraph {
    #[deref]
    list: FlatList,
}

impl Widget for SessionGraph {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        while self.list.draw_walk(cx, scope, walk).is_step() {
            let sessions = crate::SESSIONS.read().unwrap().clone();
            
            let ts_x = 40.0;
        let ts_y = 100.0;
        let n_width = 160.0;
        let n_height = 50.0;
        let h_gap = 80.0;
        let v_gap = 20.0;

        let _p = crate::theme::Palette::current();

        // 1. Draw Team Server Node
        if let Some(ts_node) = self.list.item(cx, id!(ts_node), id!(Node)) {
            let lbl = ts_node.label(cx, ids!(lbl));
            lbl.set_text(cx, "TEAM SERVER (127.0.0.1)");
            let _ = ts_node.draw_walk(cx, scope, Walk {
                abs_pos: Some(dvec2(ts_x as f64, ts_y as f64)),
                ..Walk::default()
            });
        }

        // 2. Draw Sessions
        let start_y = 40.0;
        for (i, session) in sessions.iter().enumerate() {
            let sx = ts_x + n_width + h_gap;
            let sy = start_y + (i as f32) * (n_height + v_gap);
            
            // Draw HLine from TS to Session
            if let Some(hline) = self.list.item(cx, LiveId::from_num(1, i as u64), id!(HLine)) {
                let line_y = sy + n_height / 2.0;
                let _ = hline.draw_walk(cx, scope, Walk {
                    abs_pos: Some(dvec2((ts_x + n_width) as f64, line_y as f64)),
                    width: Size::Fixed(h_gap as f64),
                    ..Walk::default()
                });
            }

            // Draw Session Node
            if let Some(node) = self.list.item(cx, LiveId::from_num(2, i as u64), id!(Node)) {
                let lbl = node.label(cx, ids!(lbl));
                
                // Construct detailed display text similar to Cobalt Strike
                let admin_star = if session.is_admin != 0 { "*" } else { "" };
                let os_icon = if session.os.to_lowercase().contains("windows") { "🪟" } else if session.os.to_lowercase().contains("mac") { "🍎" } else { "🐧" };
                let arch_str = if session.arch == 86 { "x86" } else { "x64" };
                
                lbl.set_text(cx, &format!("{} {}{}@{} (PID: {} {})", os_icon, session.username, admin_star, session.hostname, session.pid, arch_str));
                
                let _ = node.draw_walk(cx, scope, Walk {
                    abs_pos: Some(dvec2(sx as f64, sy as f64)),
                    ..Walk::default()
                });
            }
        }
        
        // We should draw a VLine connecting the HLines back to the Team Server
        if !sessions.is_empty() {
            let first_sy = start_y + n_height / 2.0;
            let last_sy = start_y + ((sessions.len() - 1) as f32) * (n_height + v_gap) + n_height / 2.0;
            if last_sy >= first_sy {
                if let Some(vline) = self.list.item(cx, id!(ts_vline), id!(VLine)) {
                    let _ = vline.draw_walk(cx, scope, Walk {
                        abs_pos: Some(dvec2((ts_x + n_width) as f64, first_sy as f64)),
                        height: Size::Fixed((last_sy - first_sy + 2.0) as f64),
                        ..Walk::default()
                    });
                    
                    // Draw connecting horizontal stub from TS to the VLine
                    let ts_mid_y = ts_y + n_height / 2.0;
                    if let Some(ts_stub) = self.list.item(cx, id!(ts_stub), id!(HLine)) {
                        let _ = ts_stub.draw_walk(cx, scope, Walk {
                            abs_pos: Some(dvec2((ts_x + n_width) as f64, ts_mid_y as f64)),
                            width: Size::Fixed(20.0),
                            ..Walk::default()
                        });
                    }
                    // Also adjust VLine to cover ts_mid_y if needed
                    let min_y = first_sy.min(ts_mid_y);
                    let max_y = last_sy.max(ts_mid_y);
                    let _ = vline.draw_walk(cx, scope, Walk {
                        abs_pos: Some(dvec2((ts_x + n_width + 20.0) as f64, min_y as f64)),
                        height: Size::Fixed((max_y - min_y + 2.0) as f64),
                        ..Walk::default()
                    });
                }
            }
        }
        } // end while

        DrawStep::done()
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        self.list.handle_event(cx, event, scope);
    }
}
