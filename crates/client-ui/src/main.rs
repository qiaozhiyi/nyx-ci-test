//! Nyx operator GUI — G1 skeleton (Makepad 2.0).
//!
//! Three things only:
//!  1. Connection bar (server URL + Connect button + status dot).
//!  2. Left panel: virtualized session table ([`SessionList`] widget).
//!  3. Center: selection placeholder ("session X selected — G2 wires the console").
//!  4. Bottom: global event log (drains the bridge's log_lines).
//!
//! Data lives in [`bridge`] (off-thread). This file drains snapshots in
//! `handle_signal` and stuffs them into the two [`LazyLock<RwLock<..>>`]
//! globals that the virtualized list widgets read in `draw_walk` — the same
//! pattern Makepad's own `todo` example uses. No blocking, no network here.

pub use makepad_widgets;
use makepad_widgets::*;

pub mod bridge;

use std::sync::{LazyLock, RwLock};

use bridge::{Bridge, Cmd, SessionView, Snapshot};

// ── shared UI state, read by the list widgets during draw ───────────────────
// LazyLock<RwLock<..>> mirrors the `todo` example exactly. Draw is on the UI
// thread and single-threaded, so the write-lock in apply_snapshot() never
// contends in practice; the RwLock is just the documented Makepad idiom.

static SESSIONS: LazyLock<RwLock<Vec<SessionView>>> = LazyLock::new(|| RwLock::new(Vec::new()));
static LOG_LINES: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

app_main!(App);

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*

    // ── dark "native pro" palette as DSL consts (inline hex; Makepad DSL
    //    composites in linear so these read right on P3 panels) ────────────
    let Cbg      = #x1e2228
    let Cpanel   = #x252a31
    let Crow     = #x2b3138
    let Crowhov  = #x323a44
    let Cborder  = #x353b44
    let Cprimary = #xdfe6ee
    let Csecond  = #x8b97a3
    let Cmuted   = #x5b6573
    let Caccent  = #x3b82f6
    let Cacchov  = #x2563eb
    let Csuccess = #x22c55e
    let Cdanger  = #xef4444

    // ── session row (one beacon) ────────────────────────────────────────────
    let SessionRow = View{
        width: Fill height: 30
        padding: {left: 12.0 right: 12.0}
        flow: Right spacing: 8.0
        align: {y: 0.5}
        draw_bg: {color: Crow, color_hover: Crowhov}

        host := Label{
            width: 140
            text: "hostname"
            draw_text: {color: Cprimary, text_style: {font_size: 12.0}}
        }
        user := Label{
            width: 110
            text: "user"
            draw_text: {color: Csecond, text_style: {font_size: 12.0}}
        }
        os := Label{
            width: Fill
            text: "os"
            draw_text: {color: Cmuted, text_style: {font_size: 11.0}}
        }
        admin := Label{
            width: 44
            text: ""
            draw_text: {color: Cdanger, text_style: {font_size: 11.0}}
        }
        pend := Label{
            width: 30
            text: "0"
            draw_text: {color: Caccent, text_style: {font_size: 11.0}}
        }
    }

    let EmptySessions = View{
        width: Fill height: Fill
        align: Center flow: Down spacing: 8.0
        Label{text: "No sessions" draw_text: {color: Cmuted, text_style: {font_size: 14.0}}}
        Label{text: "Connect to a team server to list beacons" draw_text: {color: Cmuted, text_style: {font_size: 11.0}}}
    }

    mod.widgets.SessionListBase = #(SessionList::register_widget(vm))
    mod.widgets.SessionList = set_type_default() do mod.widgets.SessionListBase{
        width: Fill height: Fill
        list := PortalList{
            width: Fill height: Fill
            spacing: 1.0
            scroll_bar: ScrollBar{}
            Item := CachedView{SessionRow{}}
            Empty := CachedView{EmptySessions{}}
        }
    }

    // ── event-log row ───────────────────────────────────────────────────────
    let LogLine = View{
        width: Fill height: Fit
        padding: {top: 2.0 bottom: 2.0 left: 10.0 right: 10.0}
        line := Label{
            width: Fill
            text: ""
            draw_text: {color: Csecond, text_style: {font_size: 11.0}}
        }
    }
    mod.widgets.LogListBase = #(LogList::register_widget(vm))
    mod.widgets.LogList = set_type_default() do mod.widgets.LogListBase{
        width: Fill height: Fill
        list := PortalList{
            width: Fill height: Fill
            spacing: 0.0
            scroll_bar: ScrollBar{}
            Item := CachedView{LogLine{}}
        }
    }

    let app = startup() do #(App::script_component(vm)){
        ui: Root{
            on_startup: ||{ ui.main_view.render() }
            main_window := Window{
                window: {inner_size: vec2(1280, 800)}
                pass: {clear_color: Cbg}
                body +: {
                    width: Fill height: Fill
                    flow: Down spacing: 0

                    // ── connection bar ─────────────────────────────────────
                    SolidView{
                        width: Fill height: 48
                        padding: {left: 16.0 right: 16.0}
                        flow: Right spacing: 10.0
                        align: {y: 0.5}
                        draw_bg: {color: Cpanel}

                        Label{
                            text: "NYX"
                            draw_text: {color: Caccent, text_style: {font_size: 16.0}}
                        }
                        server_input := TextInput{
                            width: 320 height: 30
                            padding: {left: 10.0 right: 10.0}
                            text: "http://127.0.0.1:8443"
                            empty_text: "team server URL"
                            draw_bg: {
                                color: Cbg color_hover: Cbg color_focus: Cbg
                                border_color: Cborder border_color_focus: Caccent
                                border_radius: 4.0
                            }
                            draw_text: {
                                color: Cprimary color_hover: Cprimary color_focus: Cprimary
                                color_empty: Cmuted
                            }
                            draw_cursor: {color: Caccent}
                        }
                        connect_btn := Button{
                            text: "Connect"
                            width: 90 height: 30
                            draw_bg: {color: Caccent, color_hover: Cacchov, border_radius: 4.0}
                            draw_text: {color: #ffffff}
                        }
                        status_dot := View{
                            width: 40 height: 16
                            flow: Overlay
                            align: {x: 0.0 y: 0.5}
                            dot_on := View{
                                width: 10 height: 10
                                draw_bg: {color: Csuccess, border_radius: 5.0}
                                visible: false
                            }
                            dot_off := View{
                                width: 10 height: 10
                                draw_bg: {color: Cdanger, border_radius: 5.0}
                            }
                        }
                        status_text := Label{
                            text: "disconnected"
                            draw_text: {color: Cmuted, text_style: {font_size: 11.0}}
                        }
                    }

                    // ── main body: sessions | center ───────────────────────
                    View{
                        width: Fill height: Fill
                        flow: Right spacing: 0

                        View{
                            width: 440 height: Fill
                            flow: Down spacing: 0
                            draw_bg: {color: Cpanel}
                            View{
                                width: Fill height: 28
                                padding: {left: 12.0}
                                align: {y: 0.5}
                                draw_bg: {color: Crow}
                                Label{text: "SESSIONS" draw_text: {color: Cmuted, text_style: {font_size: 10.0}}}
                            }
                            session_list := mod.widgets.SessionList{}
                        }

                        center := View{
                            width: Fill height: Fill
                            align: Center flow: Down spacing: 8.0
                            center_text := Label{
                                text: "Select a session"
                                draw_text: {color: Cmuted, text_style: {font_size: 16.0}}
                            }
                            center_sub := Label{
                                text: "Interactive console arrives in G2"
                                draw_text: {color: Cmuted, text_style: {font_size: 11.0}}
                            }
                        }
                    }

                    // ── event log ─────────────────────────────────────────
                    View{
                        width: Fill height: 140
                        flow: Down spacing: 0
                        draw_bg: {color: Cpanel}
                        View{
                            width: Fill height: 24
                            padding: {left: 12.0}
                            align: {y: 0.5}
                            draw_bg: {color: Crow}
                            Label{text: "EVENT LOG" draw_text: {color: Cmuted, text_style: {font_size: 10.0}}}
                        }
                        log_list := mod.widgets.LogList{}
                    }
                }
            }
        }
    }
    app
}

// ── App ─────────────────────────────────────────────────────────────────────

#[derive(Script, ScriptHook)]
pub struct App {
    #[live]
    ui: WidgetRef,
    #[rust]
    bridge: Option<Bridge>,
    #[rust]
    selected: Option<usize>,
}

impl App {
    /// Lazily spawn the bridge on first Connect.
    fn ensure_bridge(&mut self) {
        if self.bridge.is_none() {
            self.bridge = Some(bridge::spawn());
        }
    }

    /// Merge a snapshot into the shared globals + update status + redraw.
    fn apply_snapshot(&mut self, cx: &mut Cx, snap: Snapshot) {
        if !snap.sessions.is_empty() {
            *SESSIONS.write().unwrap() = snap.sessions;
        }
        {
            let mut log = LOG_LINES.write().unwrap();
            for line in snap.log_lines {
                log.push(line);
            }
            // bound the log (defends against an unbounded server flood)
            if log.len() > 4096 {
                let drop = log.len() - 4096;
                log.drain(..drop);
            }
        }
        self.set_status(cx, snap.connected);
        self.ui.redraw(cx);
    }

    fn set_status(&self, cx: &mut Cx, connected: bool) {
        // Two static dots (one green, one red); toggle visibility. Avoids the
        // unverified `apply_over`/`live!` rust-side color API — uses only the
        // documented `.set_visible()` from the `todo` example.
        self.ui.view(cx, ids!(dot_on)).set_visible(cx, connected);
        self.ui.view(cx, ids!(dot_off)).set_visible(cx, !connected);
        self.ui
            .label(cx, ids!(status_text))
            .set_text(cx, if connected { "connected" } else { "disconnected" });
    }
}

impl MatchEvent for App {
    fn handle_startup(&mut self, cx: &mut Cx) {
        self.set_status(cx, false);
        self.ui.redraw(cx);
    }

    fn handle_actions(&mut self, cx: &mut Cx, actions: &Actions) {
        let connect_clicked = self.ui.button(cx, ids!(connect_btn)).clicked(actions);
        let entered = self
            .ui
            .text_input(cx, ids!(server_input))
            .returned(actions)
            .is_some();
        if connect_clicked || entered {
            self.ensure_bridge();
            if let Some(b) = &self.bridge {
                let url = self.ui.text_input(cx, ids!(server_input)).text();
                let _ = b.from_ui.send(Cmd::Connect { server: url });
            }
        }

        // Session row selection (a row is "clicked" if the PortalList reports
        // an action for it).
        let session_list = self.ui.widget(cx, ids!(session_list));
        let list = session_list.portal_list(cx, ids!(list));
        for (item_id, _item) in list.items_with_actions(actions) {
            self.selected = Some(item_id);
            let sessions = SESSIONS.read().unwrap();
            let s = sessions.get(item_id);
            let text = match s {
                Some(s) => format!("● {} @ {}   (id {:.8})", s.hostname, s.username, s.id),
                None => "Select a session".to_string(),
            };
            let sub = if s.is_some() {
                "Interactive console arrives in G2".to_string()
            } else {
                String::new()
            };
            self.ui.label(cx, ids!(center_text)).set_text(cx, &text);
            self.ui.label(cx, ids!(center_sub)).set_text(cx, &sub);
            self.ui.redraw(cx);
        }
    }

    fn handle_signal(&mut self, cx: &mut Cx) {
        // Drain every pending snapshot the bridge pushed since last signal.
        while let Some(b) = self.bridge.as_mut() {
            match b.to_ui.try_recv() {
                Ok(snap) => self.apply_snapshot(cx, snap),
                Err(_) => break,
            }
        }
    }
}

impl AppMain for App {
    fn script_mod(vm: &mut ScriptVm) -> ScriptValue {
        crate::makepad_widgets::script_mod(vm);
        self::script_mod(vm)
    }
    fn handle_event(&mut self, cx: &mut Cx, event: &Event) {
        self.match_event(cx, event);
        self.ui.handle_event(cx, event, &mut Scope::empty());
    }
}

// ── SessionList widget (virtualized, reads SESSIONS global) ─────────────────

#[derive(Script, ScriptHook, Widget)]
struct SessionList {
    #[deref]
    view: View,
}

impl Widget for SessionList {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let sessions = SESSIONS.read().unwrap().clone();
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                if sessions.is_empty() {
                    list.set_item_range(cx, 0, 1);
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let item = list.item(cx, item_id, id!(Empty));
                        item.draw_all_unscoped(cx);
                    }
                } else {
                    list.set_item_range(cx, 0, sessions.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(s) = sessions.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));
                        item.label(cx, ids!(host)).set_text(cx, &s.hostname);
                        item.label(cx, ids!(user)).set_text(cx, &s.username);
                        item.label(cx, ids!(os)).set_text(cx, &s.os);
                        item.label(cx, ids!(admin))
                            .set_text(cx, if s.is_admin != 0 { "ADMIN" } else { "" });
                        item.label(cx, ids!(pend)).set_text(cx, &s.pending.to_string());
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

// ── LogList widget (virtualized, reads LOG_LINES global) ────────────────────

#[derive(Script, ScriptHook, Widget)]
struct LogList {
    #[deref]
    view: View,
}

impl Widget for LogList {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let lines = LOG_LINES.read().unwrap().clone();
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                list.set_item_range(cx, 0, lines.len());
                while let Some(item_id) = list.next_visible_item(cx) {
                    let Some(line) = lines.get(item_id) else { continue };
                    let item = list.item(cx, item_id, id!(Item));
                    item.label(cx, ids!(line)).set_text(cx, line);
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
