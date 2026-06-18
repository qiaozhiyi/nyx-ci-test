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
pub mod widgets;

use crate::widgets::{
    bof_panel::{BofEntry, BofPanel, BofStatus, BOFS},
    cred_table::CredTable,
    file_tree::FileTree,
    process_table::ProcessTable,
};

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
        width: Fill height: 30
        flow: Overlay
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov

        // Label row (the visible content).
        content := View{
            width: Fill height: Fill
            padding: Inset{left: 12.0 right: 12.0}
            flow: Right spacing: 8.0
            align: Align{y: 0.5}
            host := Label{
                width: 140
                text: "hostname"
                draw_text.color: Cprimary
                draw_text.text_style.font_size: 12.0
            }
            user := Label{
                width: 110
                text: "user"
                draw_text.color: Csecond
                draw_text.text_style.font_size: 12.0
            }
            os := Label{
                width: Fill
                text: "os"
                draw_text.color: Cmuted
                draw_text.text_style.font_size: 11.0
            }
            admin := Label{
                width: 44
                text: ""
                draw_text.color: Cdanger
                draw_text.text_style.font_size: 11.0
            }
            pend := Label{
                width: 30
                text: "0"
                draw_text.color: Caccent
                draw_text.text_style.font_size: 11.0
            }
        }
        // Invisible click target on top.
        select := Button{
            width: Fill height: Fill
            text: ""
            draw_bg.color: #x00000000
            draw_bg.color_hover: #x00000000
            draw_bg.color_down: #x00000000
            draw_bg.border_size: 0.0
            draw_text.color: #x00000000
        }
    }

    let EmptySessions = View{
        width: Fill height: Fill
        align: Center flow: Down spacing: 8.0
        Label{text: "No sessions" draw_text.color: Cmuted draw_text.text_style.font_size: 14.0}
        Label{text: "Connect to a team server to list beacons" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
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
        padding: Inset{top: 2.0 bottom: 2.0 left: 10.0 right: 10.0}
        line := Label{
            width: Fill
            text: ""
            draw_text.color: Csecond
            draw_text.text_style.font_size: 11.0
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

    // ── G2 feature widgets (BOF / files / processes / credentials) ──────────
    // Each mirrors SessionList/LogList: a `register_widget` + a `set_type_default`
    // wrapper mounting a PortalList with an `Item` CachedView (whose inner ids
    // match what the Rust impl sets) and an `Empty` CachedView fallback.

    // BOF loader panel — rows: name / status / args
    let BofRow = View{
        width: Fill height: 26
        padding: Inset{left: 12.0 right: 12.0}
        flow: Right spacing: 10.0
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        name := Label{width: 200 text: "" draw_text.color: Cprimary draw_text.text_style.font_size: 12.0}
        status := Label{width: 70 text: "" draw_text.color: Csecond draw_text.text_style.font_size: 11.0}
        args := Label{width: Fill text: "" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    let BofEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: 8.0
        Label{text: "No BOFs executed" draw_text.color: Cmuted draw_text.text_style.font_size: 14.0}
        Label{text: "BOF loader input arrives in G2 console" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    mod.widgets.BofPanelBase = #(BofPanel::register_widget(vm))
    mod.widgets.BofPanel = set_type_default() do mod.widgets.BofPanelBase{
        width: Fill height: Fill
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{BofRow{}} Empty := CachedView{BofEmpty{}}}
    }

    // File tree — rows: name / size / modified
    let FileRow = View{
        width: Fill height: 24
        padding: Inset{left: 12.0 right: 12.0}
        flow: Right spacing: 10.0
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        name := Label{width: Fill text: "" draw_text.color: Cprimary draw_text.text_style.font_size: 12.0}
        size := Label{width: 90 text: "" draw_text.color: Csecond draw_text.text_style.font_size: 11.0}
        modified := Label{width: 150 text: "" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    let FileEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: 8.0
        Label{text: "No remote path listed" draw_text.color: Cmuted draw_text.text_style.font_size: 14.0}
        Label{text: "Run ls on a session to browse" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    mod.widgets.FileTreeBase = #(FileTree::register_widget(vm))
    mod.widgets.FileTree = set_type_default() do mod.widgets.FileTreeBase{
        width: Fill height: Fill
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{FileRow{}} Empty := CachedView{FileEmpty{}}}
    }

    // Process table — rows: pid / ppid / name / user / arch
    let ProcRow = View{
        width: Fill height: 24
        padding: Inset{left: 12.0 right: 12.0}
        flow: Right spacing: 10.0
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        pid := Label{width: 60 text: "" draw_text.color: Caccent draw_text.text_style.font_size: 11.0}
        ppid := Label{width: 60 text: "" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
        name := Label{width: Fill text: "" draw_text.color: Cprimary draw_text.text_style.font_size: 12.0}
        user := Label{width: 100 text: "" draw_text.color: Csecond draw_text.text_style.font_size: 11.0}
        arch := Label{width: 50 text: "" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    let ProcEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: 8.0
        Label{text: "No processes" draw_text.color: Cmuted draw_text.text_style.font_size: 14.0}
        Label{text: "Run ps on a session" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    mod.widgets.ProcessTableBase = #(ProcessTable::register_widget(vm))
    mod.widgets.ProcessTable = set_type_default() do mod.widgets.ProcessTableBase{
        width: Fill height: Fill
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{ProcRow{}} Empty := CachedView{ProcEmpty{}}}
    }

    // Credential vault — rows: source / principal / kind / value(masked)
    let CredRow = View{
        width: Fill height: 26
        padding: Inset{left: 12.0 right: 12.0}
        flow: Right spacing: 10.0
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        source := Label{width: 120 text: "" draw_text.color: Csecond draw_text.text_style.font_size: 11.0}
        principal := Label{width: 160 text: "" draw_text.color: Cprimary draw_text.text_style.font_size: 12.0}
        kind := Label{width: 80 text: "" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
        value := Label{width: Fill text: "" draw_text.color: Cdanger draw_text.text_style.font_size: 11.0}
    }
    let CredEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: 8.0
        Label{text: "No credentials" draw_text.color: Cmuted draw_text.text_style.font_size: 14.0}
        Label{text: "Credentials surface as beacons collect them" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }
    mod.widgets.CredTableBase = #(CredTable::register_widget(vm))
    mod.widgets.CredTable = set_type_default() do mod.widgets.CredTableBase{
        width: Fill height: Fill
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{CredRow{}} Empty := CachedView{CredEmpty{}}}
    }

    let app = startup() do #(App::script_component(vm)){
        ui: Root{
            // No `on_startup` render() call: our dynamic content is driven by
            // custom widgets' draw_walk (PortalList), retriggered via
            // self.ui.redraw(cx) from handle_signal/handle_actions — NOT by the
            // 2.0 `on_render` closure model. Calling ui.main_view.render()
            // here segfaulted in release because main_view has no on_render
            // handler (counter's does). Counter needs it because it uses
            // on_render for its label; we don't.
            main_window := Window{
                window.inner_size: vec2(1280, 800)
                pass.clear_color: Cbg
                body +: {
                    width: Fill height: Fill
                    flow: Down spacing: 0

                    // ── connection bar ─────────────────────────────────────
                    SolidView{
                        width: Fill height: 48
                        padding: Inset{left: 16.0 right: 16.0}
                        flow: Right spacing: 10.0
                        align: Align{y: 0.5}
                        draw_bg.color: Cpanel

                        Label{
                            text: "NYX"
                            draw_text.color: Caccent
                            draw_text.text_style.font_size: 16.0
                        }
                        server_input := TextInput{
                            width: 320 height: 30
                            padding: Inset{left: 10.0 right: 10.0}
                            text: "http://127.0.0.1:8443"
                            empty_text: "team server URL"
                            draw_bg.color: Cbg
                            draw_bg.color_hover: Cbg
                            draw_bg.color_focus: Cbg
                            draw_bg.border_color: Cborder
                            draw_bg.border_color_focus: Caccent
                            draw_bg.border_radius: 4.0
                            draw_text.color: Cprimary
                            draw_text.color_hover: Cprimary
                            draw_text.color_focus: Cprimary
                            draw_text.color_empty: Cmuted
                            draw_cursor.color: Caccent
                        }
                        connect_btn := Button{
                            text: "Connect"
                            width: 90 height: 30
                            draw_bg.color: Caccent
                            draw_bg.color_hover: Cacchov
                            draw_bg.border_radius: 4.0
                            draw_text.color: #ffffff
                        }
                        status_dot := View{
                            width: 40 height: 16
                            flow: Overlay
                            align: Align{x: 0.0 y: 0.5}
                            dot_on := View{
                                width: 10 height: 10
                                draw_bg.color: Csuccess
                                draw_bg.border_radius: 5.0
                                visible: false
                            }
                            dot_off := View{
                                width: 10 height: 10
                                draw_bg.color: Cdanger
                                draw_bg.border_radius: 5.0
                            }
                        }
                        status_text := Label{
                            text: "disconnected"
                            draw_text.color: Cmuted
                            draw_text.text_style.font_size: 11.0
                        }
                    }

                    // ── main body: sessions | center ───────────────────────
                    View{
                        width: Fill height: Fill
                        flow: Right spacing: 0

                        View{
                            width: 440 height: Fill
                            flow: Down spacing: 0
                            draw_bg.color: Cpanel
                            View{
                                width: Fill height: 28
                                padding: Inset{left: 12.0}
                                align: Align{y: 0.5}
                                draw_bg.color: Crow
                                Label{text: "SESSIONS" draw_text.color: Cmuted draw_text.text_style.font_size: 10.0}
                            }
                            session_list := mod.widgets.SessionList{}
                        }

                        center := View{
                            width: Fill height: Fill
                            flow: Down spacing: 0
                            draw_bg.color: Cbg

                            // ── tab bar ────────────────────────────────────
                            View{
                                width: Fill height: 32
                                padding: Inset{left: 8.0}
                                flow: Right spacing: 0
                                align: Align{y: 0.5}
                                draw_bg.color: Cpanel
                                tab_console := Button{
                                    text: "CONSOLE"
                                    width: 96 height: 26
                                    draw_bg.color: Cpanel
                                    draw_bg.color_hover: Crow
                                    draw_bg.color_down: Crow
                                    draw_bg.border_size: 0.0
                                    draw_text.color: Caccent
                                    draw_text.color_hover: Caccent
                                    draw_text.text_style.font_size: 11.0
                                }
                                tab_bof := Button{
                                    text: "BOF"
                                    width: 72 height: 26
                                    draw_bg.color: Cpanel
                                    draw_bg.color_hover: Crow
                                    draw_bg.color_down: Crow
                                    draw_bg.border_size: 0.0
                                    draw_text.color: Cmuted
                                    draw_text.color_hover: Cprimary
                                    draw_text.text_style.font_size: 11.0
                                }
                                tab_files := Button{
                                    text: "FILES"
                                    width: 72 height: 26
                                    draw_bg.color: Cpanel
                                    draw_bg.color_hover: Crow
                                    draw_bg.color_down: Crow
                                    draw_bg.border_size: 0.0
                                    draw_text.color: Cmuted
                                    draw_text.color_hover: Cprimary
                                    draw_text.text_style.font_size: 11.0
                                }
                                tab_procs := Button{
                                    text: "PROCESSES"
                                    width: 96 height: 26
                                    draw_bg.color: Cpanel
                                    draw_bg.color_hover: Crow
                                    draw_bg.color_down: Crow
                                    draw_bg.border_size: 0.0
                                    draw_text.color: Cmuted
                                    draw_text.color_hover: Cprimary
                                    draw_text.text_style.font_size: 11.0
                                }
                                tab_creds := Button{
                                    text: "CREDENTIALS"
                                    width: 110 height: 26
                                    draw_bg.color: Cpanel
                                    draw_bg.color_hover: Crow
                                    draw_bg.color_down: Crow
                                    draw_bg.border_size: 0.0
                                    draw_text.color: Cmuted
                                    draw_text.color_hover: Cprimary
                                    draw_text.text_style.font_size: 11.0
                                }
                            }

                            // ── tab bodies (toggled via set_visible) ───────
                            pane_console := View{
                                width: Fill height: Fill
                                align: Center flow: Down spacing: 8.0
                                center_text := Label{
                                    text: "Select a session"
                                    draw_text.color: Cmuted
                                    draw_text.text_style.font_size: 16.0
                                }
                                center_sub := Label{
                                    text: "Interactive shell arrives in G2 console"
                                    draw_text.color: Cmuted
                                    draw_text.text_style.font_size: 11.0
                                }
                            }
                            pane_bof := View{
                                width: Fill height: Fill
                                visible: false
                                mod.widgets.BofPanel{}
                            }
                            pane_files := View{
                                width: Fill height: Fill
                                visible: false
                                mod.widgets.FileTree{}
                            }
                            pane_procs := View{
                                width: Fill height: Fill
                                visible: false
                                mod.widgets.ProcessTable{}
                            }
                            pane_creds := View{
                                width: Fill height: Fill
                                visible: false
                                mod.widgets.CredTable{}
                            }
                        }
                    }

                    // ── event log ─────────────────────────────────────────
                    View{
                        width: Fill height: 140
                        flow: Down spacing: 0
                        draw_bg.color: Cpanel
                        View{
                            width: Fill height: 24
                            padding: Inset{left: 12.0}
                            align: Align{y: 0.5}
                            draw_bg.color: Crow
                            Label{text: "EVENT LOG" draw_text.color: Cmuted draw_text.text_style.font_size: 10.0}
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
    #[rust]
    active_tab: Tab,
}

/// Which center pane is shown. Defaults to Console. The tab bar is a row of
/// `Button`s (not Labels) so click detection works via the standard `.clicked`
/// action — matching the `todo` example's use of clickable buttons.
#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Console,
    Bof,
    Files,
    Procs,
    Creds,
}

impl Default for Tab {
    fn default() -> Self {
        Tab::Console
    }
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
        // Route BOF lifecycle updates into the BOF history global.
        if !snap.bof_updates.is_empty() {
            let mut bofs = BOFS.write().unwrap();
            for u in snap.bof_updates {
                bofs.push(BofEntry {
                    name: u.name,
                    args: u.args,
                    status: match u.status {
                        bridge::BofState::Pending => BofStatus::Pending,
                        bridge::BofState::Done => BofStatus::Done,
                        bridge::BofState::Error => BofStatus::Error,
                    },
                });
                // Cap the history so it can't grow unbounded.
                if bofs.len() > 1024 {
                    let drop = bofs.len() - 1024;
                    bofs.drain(..drop);
                }
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

    /// Switch the center pane to `tab`: hide every pane, show the selected one.
    fn set_active_tab(&mut self, cx: &mut Cx, tab: Tab) {
        if self.active_tab == tab {
            return;
        }
        self.active_tab = tab;
        // Show only the active pane; hide the rest. Pane ids are static so we
        // use the verified `ids!()` macro rather than a runtime lookup.
        let panes = [
            (Tab::Console, ids!(pane_console)),
            (Tab::Bof, ids!(pane_bof)),
            (Tab::Files, ids!(pane_files)),
            (Tab::Procs, ids!(pane_procs)),
            (Tab::Creds, ids!(pane_creds)),
        ];
        for (t, id) in panes {
            self.ui.view(cx, id).set_visible(cx, t == tab);
        }
        self.ui.redraw(cx);
    }
}

impl MatchEvent for App {
    fn handle_startup(&mut self, cx: &mut Cx) {
        self.set_status(cx, false);
        self.ui.redraw(cx);
    }

    fn handle_actions(&mut self, cx: &mut Cx, actions: &Actions) {
        // Tab bar clicks — switch the center pane.
        if self.ui.button(cx, ids!(tab_console)).clicked(actions) {
            self.set_active_tab(cx, Tab::Console);
        }
        if self.ui.button(cx, ids!(tab_bof)).clicked(actions) {
            self.set_active_tab(cx, Tab::Bof);
        }
        if self.ui.button(cx, ids!(tab_files)).clicked(actions) {
            self.set_active_tab(cx, Tab::Files);
        }
        if self.ui.button(cx, ids!(tab_procs)).clicked(actions) {
            self.set_active_tab(cx, Tab::Procs);
        }
        if self.ui.button(cx, ids!(tab_creds)).clicked(actions) {
            self.set_active_tab(cx, Tab::Creds);
        }

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

        // Session row selection. `items_with_actions` only yields rows whose
        // child widgets fired an action, so each row carries an invisible
        // `select` Button (overlay) — we check it here. Matches the `todo`
        // example's per-row `delete` pattern.
        let session_list = self.ui.widget(cx, ids!(session_list));
        let list = session_list.portal_list(cx, ids!(list));
        for (item_id, item) in list.items_with_actions(actions) {
            if item.button(cx, ids!(select)).clicked(actions) {
                self.selected = Some(item_id);
                let sessions = SESSIONS.read().unwrap();
                let s = sessions.get(item_id);
                let text = match s {
                    Some(s) => format!("● {} @ {}   (id {:.8})", s.hostname, s.username, s.id),
                    None => "Select a session".to_string(),
                };
                let sub = if s.is_some() {
                    "Interactive console arrives in G2 console".to_string()
                } else {
                    String::new()
                };
                self.ui.label(cx, ids!(center_text)).set_text(cx, &text);
                self.ui.label(cx, ids!(center_sub)).set_text(cx, &sub);
                self.ui.redraw(cx);
            }
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
                    // Empty list: render zero rows. We deliberately do NOT use
                    // the todo-style `set_item_range(0,1)` + Empty-view trick
                    // here: drawing a single Empty row on first paint (before
                    // the layout pass completes) causes the PortalList to
                    // measure 0 tall, which cascades to a 0x0 window that never
                    // comes onscreen (verified via CGWindowList). The todo
                    // example sidesteps this by pre-populating its list at
                    // startup, so its empty branch never runs on first paint.
                    // We just render nothing; a separate static EmptySessions
                    // overlay could be added later if desired.
                    list.set_item_range(cx, 0, 0);
                } else {
                    list.set_item_range(cx, 0, sessions.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(s) = sessions.get(item_id) else { continue };
                        let item = list.item(cx, item_id, id!(Item));
                        // Labels live under `content` now (overlay layout).
                        item.label(cx, ids!(content.host)).set_text(cx, &s.hostname);
                        item.label(cx, ids!(content.user)).set_text(cx, &s.username);
                        item.label(cx, ids!(content.os)).set_text(cx, &s.os);
                        item.label(cx, ids!(content.admin))
                            .set_text(cx, if s.is_admin != 0 { "ADMIN" } else { "" });
                        item.label(cx, ids!(content.pend)).set_text(cx, &s.pending.to_string());
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
