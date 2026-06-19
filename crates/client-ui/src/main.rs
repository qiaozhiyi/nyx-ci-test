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
pub mod theme;
pub mod widgets;

use crate::theme::Palette;

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
pub static IS_DARK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// Index of the currently-selected session row, or usize::MAX for none.
/// SessionList::draw_walk reads this to tint the selected row's background
/// (Crowsel) — the only way to give per-row selection feedback through a
/// virtualized PortalList (the App can't reach inside individual rows).
static SELECTED_SESSION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

app_main!(App);

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*

    // ── One Dark Pro palette ───────────────────────────────────────────────
    // Deep purple-charcoal base, single magenta signal (#C586C0), teal success,
    // light-blue info. These hex values MIRROR `Palette::dark()` in theme.rs —
    // the dynamic ramp consulted at draw time so the theme toggle repaints
    // consistently. Keep the two in lockstep: change one, change both.
    let Cbg       = #x1A1A25  // app background — deepest surface
    let Cbar      = #x1E1E2E  // recessed secondary bars / tab bar
    let Cpanel    = #x1E1E2E  // side panels + event-log shell
    let Crow      = #x1E1E2E  // table/data-row base
    let Crowhov   = #x2A2A3A  // row hover
    let Crowsel   = #x3A2A3E  // row selected (magenta-tinted)
    let Celev     = #x252533  // brightest surface — column headers / dialog card
    let Cborder   = #x2A2A3A  // hairline dividers
    let Cprimary  = #xCCCCCC  // primary text
    let Csecond   = #xAAAAAA  // secondary text
    let Cmuted    = #x8A8A8A  // muted text / column labels
    let Caccent   = #xC586C0  // signature magenta accent
    let Cacchov   = #xD89ED4  // accent hover
    let Csuccess  = #x4EC9B0  // success / online (teal)
    let Cdanger   = #xF44747  // danger / alert
    let Cwarn     = #xDCDCAA  // warning / pending / secrets
    let Cinfo     = #x9CDCFE  // info / command keyword
    let Cunder    = #xC586C0  // active-tab underline (magenta)
    let Cradius   = 6.0       // unified corner radius (cards / buttons / inputs)
    let Cradius_s = 3.0       // small radius (tags / badges)
    // Shared layout metrics so column headers and data rows stay perfectly
    // aligned: both reference these instead of re-typing the same numbers.
    let Cpad      = 14.0      // table row / header horizontal inset
    let Cgap      = 16.0      // column gap inside rows / headers

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
            user := Label{
                width: 112
                text: "user"
                draw_text.color: Csecond
                draw_text.text_style: theme.font_regular{font_size: 13}
            }
            os := Label{
                width: Fill
                text: "os"
                draw_text.color: Cmuted
                draw_text.text_style: theme.font_regular{font_size: 13}
            }
            admin := Label{
                width: 56
                text: ""
                draw_text.color: Cdanger
                draw_text.text_style: theme.font_bold{font_size: theme.font_size_code}
            }
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
    }

    let EmptySessions = View{
        width: Fill height: Fill
        align: Center flow: Down spacing: 8.0
        Label{text: "No Active Beacons" draw_text.color: Cmuted draw_text.text_style.font_size: 13.0}
        Label{text: "Connect to a team server to display beacons" draw_text.color: Cmuted draw_text.text_style.font_size: 11.0}
    }

    mod.widgets.SessionListBase = #(SessionList::register_widget(vm))
    mod.widgets.SessionList = set_type_default() do mod.widgets.SessionListBase{
        width: Fill height: Fill
        flow: Down
        // Column header — a non-virtualized View pinned above the PortalList
        // so it stays put while rows scroll beneath it. Column widths/gap/pad
        // MIRROR SessionRow.content exactly, so headers line up with the data.
        header := View{
            width: Fill height: Fit
            flow: Down
            draw_bg.color: Celev
            View{
                width: Fill height: 30
                padding: Inset{left: Cpad right: Cpad}
                flow: Right spacing: Cgap
                align: Align{y: 0.5}
                Label{width: 160 text: "HOST" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 112 text: "USER" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: Fill text: "OPERATING SYSTEM" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 56 text: "PRIV" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 44 text: "QUE" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
        }
        list := PortalList{
            width: Fill height: Fill
            spacing: 1.0
            scroll_bar: ScrollBar{}
            // Two item templates: Item (normal) and ItemSel (selected, blue
            // bg). draw_walk picks per row — can't mutate bg color at runtime
            // (no safe set_color API in this Makepad version), so we use the
            // verified "different CachedView id" approach like todo's Empty.
            Item := CachedView{SessionRow{}}
            ItemSel := CachedView{SessionRow{draw_bg.color: Crowsel}}
            Empty := CachedView{EmptySessions{}}
        }
    }

    // ── event-log row (monospace — it's a tail of operator/beacon output) ────
    let LogLine = View{
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
            Item := CachedView{LogLine{}}
        }
    }

    // ── G2 feature widgets (BOF / files / processes / credentials) ──────────
    // Each mirrors SessionList/LogList: a `register_widget` + a `set_type_default`
    // wrapper mounting a PortalList with an `Item` CachedView (whose inner ids
    // match what the Rust impl sets) and an `Empty` CachedView fallback.

    // BOF loader panel — columns: OBJECT / STATUS / ARGUMENTS
    let BofRow = View{
        width: Fill height: 30
        padding: Inset{left: Cpad right: Cpad}
        flow: Right spacing: Cgap
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        name := Label{width: 240 text: "" draw_text.color: Cprimary draw_text.text_style: theme.font_regular{font_size: 13}}
        status := Label{width: 96 text: "" draw_text.color: Csecond draw_text.text_style: theme.font_regular{font_size: 13}}
        args := Label{width: Fill text: "" draw_text.color: Cmuted draw_text.text_style: theme.font_code{font_size: 12}}
    }
    let BofEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: theme.space_2
        Label{text: "No BOF runs recorded" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 13}}
        Label{text: "Execute a BOF task from the console to display history" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
    }
    mod.widgets.BofPanelBase = #(BofPanel::register_widget(vm))
    mod.widgets.BofPanel = set_type_default() do mod.widgets.BofPanelBase{
        width: Fill height: Fill
        flow: Down
        header := View{width: Fill height: Fit flow: Down draw_bg.color: Celev
            View{width: Fill height: 30 padding: Inset{left: Cpad right: Cpad} flow: Right spacing: Cgap align: Align{y: 0.5}
                Label{width: 240 text: "OBJECT" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 96 text: "STATUS" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: Fill text: "ARGUMENTS" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
        }
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{BofRow{}} Empty := CachedView{BofEmpty{}}}
    }

    // File tree — columns: NAME / SIZE / MODIFIED
    let FileRow = View{
        width: Fill height: 30
        padding: Inset{left: Cpad right: Cpad}
        flow: Right spacing: Cgap
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        name := Label{width: Fill text: "" draw_text.color: Cprimary draw_text.text_style: theme.font_regular{font_size: 13}}
        size := Label{width: 96 text: "" draw_text.color: Csecond draw_text.text_style: theme.font_code{font_size: 12}}
        modified := Label{width: 168 text: "" draw_text.color: Cmuted draw_text.text_style: theme.font_code{font_size: 12}}
    }
    let FileEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: theme.space_2
        Label{text: "No remote files listed" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 13}}
        Label{text: "Run the 'ls' command in the console to populate directory tree" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
    }
    mod.widgets.FileTreeBase = #(FileTree::register_widget(vm))
    mod.widgets.FileTree = set_type_default() do mod.widgets.FileTreeBase{
        width: Fill height: Fill
        flow: Down
        header := View{width: Fill height: Fit flow: Down draw_bg.color: Celev
            View{width: Fill height: 30 padding: Inset{left: Cpad right: Cpad} flow: Right spacing: Cgap align: Align{y: 0.5}
                Label{width: Fill text: "NAME" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 96 text: "SIZE" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 168 text: "MODIFIED" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
        }
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{FileRow{}} Empty := CachedView{FileEmpty{}}}
    }

    // Process table — columns: PID / PPID / PROCESS / USER / ARCH
    let ProcRow = View{
        width: Fill height: 30
        padding: Inset{left: Cpad right: Cpad}
        flow: Right spacing: Cgap
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        pid := Label{width: 72 text: "" draw_text.color: Caccent draw_text.text_style: theme.font_code{font_size: 12}}
        ppid := Label{width: 72 text: "" draw_text.color: Cmuted draw_text.text_style: theme.font_code{font_size: 12}}
        name := Label{width: Fill text: "" draw_text.color: Cprimary draw_text.text_style: theme.font_regular{font_size: 13}}
        user := Label{width: 140 text: "" draw_text.color: Csecond draw_text.text_style: theme.font_regular{font_size: 13}}
        arch := Label{width: 64 text: "" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 13}}
    }
    let ProcEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: theme.space_2
        Label{text: "No process list active" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 13}}
        Label{text: "Run the 'ps' command in the console to view active tasks" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
    }
    mod.widgets.ProcessTableBase = #(ProcessTable::register_widget(vm))
    mod.widgets.ProcessTable = set_type_default() do mod.widgets.ProcessTableBase{
        width: Fill height: Fill
        flow: Down
        header := View{width: Fill height: Fit flow: Down draw_bg.color: Celev
            View{width: Fill height: 30 padding: Inset{left: Cpad right: Cpad} flow: Right spacing: Cgap align: Align{y: 0.5}
                Label{width: 72 text: "PID" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 72 text: "PPID" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: Fill text: "PROCESS" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 140 text: "USER" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 64 text: "ARCH" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
        }
        list := PortalList{width: Fill height: Fill spacing: 1.0 scroll_bar: ScrollBar{}
            Item := CachedView{ProcRow{}} Empty := CachedView{ProcEmpty{}}}
    }

    // Credential vault — columns: SOURCE / PRINCIPAL / KIND / SECRET
    let CredRow = View{
        width: Fill height: 30
        padding: Inset{left: Cpad right: Cpad}
        flow: Right spacing: Cgap
        align: Align{y: 0.5}
        draw_bg.color: Crow
        draw_bg.color_hover: Crowhov
        source := Label{width: 150 text: "" draw_text.color: Csecond draw_text.text_style: theme.font_code{font_size: 12}}
        principal := Label{width: 240 text: "" draw_text.color: Cprimary draw_text.text_style: theme.font_regular{font_size: 13}}
        kind := Label{width: 100 text: "" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 13}}
        value := Label{width: Fill text: "" draw_text.color: Cwarn draw_text.text_style: theme.font_code{font_size: 12}}
    }
    let CredEmpty = View{
        width: Fill height: Fill align: Center flow: Down spacing: theme.space_2
        Label{text: "No credentials collected" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 13}}
        Label{text: "Credentials will appear here once beacons dump passwords" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
    }
    mod.widgets.CredTableBase = #(CredTable::register_widget(vm))
    mod.widgets.CredTable = set_type_default() do mod.widgets.CredTableBase{
        width: Fill height: Fill
        flow: Down
        header := View{width: Fill height: Fit flow: Down draw_bg.color: Celev
            View{width: Fill height: 30 padding: Inset{left: Cpad right: Cpad} flow: Right spacing: Cgap align: Align{y: 0.5}
                Label{width: 150 text: "SOURCE" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 240 text: "PRINCIPAL" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: 100 text: "KIND" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
                Label{width: Fill text: "SECRET" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11}}
            }
            View{width: Fill height: 1 draw_bg.color: Cborder}
        }
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
                    // flow: Overlay stacks the connect dialog on top of the
                    // main console. connect_view starts visible, main_view
                    // hidden; handle_signal flips them once the bridge reports
                    // connected:true. Mirrors CS's "connect dialog first" flow.
                    flow: Down

                    // ── connect dialog (shown until connected) ──────────────
                    connect_view := View{
                        width: Fill height: Fill
                        align: Center
                        draw_bg.color: Cbg
                        // The dialog card.
                        connect_card := SolidView{
                            width: 460 height: Fit
                            flow: Down
                            draw_bg.color: Celev
                            draw_bg.border_radius: Cradius
                            draw_bg.border_size: 1.0
                            draw_bg.border_color: Cborder

                            // Brand header: gradient logo box + wordmark + tagline.
                            // No accent stripe — One Dark doesn't use it.
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 30.0 bottom: 22.0 left: 30.0 right: 30.0}
                                flow: Down spacing: 6.0
                                View{
                                    width: Fit height: Fit
                                    flow: Right spacing: 10.0
                                    align: Align{y: 0.5}
                                    logo_box := View{
                                        width: 30 height: 30
                                        draw_bg.color: Caccent
                                        draw_bg.border_radius: 6.0
                                        align: Center
                                        logo_letter := Label{
                                            text: "N"
                                            draw_text.color: Cbg
                                            draw_text.text_style: theme.font_bold{font_size: 16}
                                        }
                                    }
                                    nyx_logo := Label{
                                        text: "Nyx Operator"
                                        draw_text.color: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 16}
                                    }
                                }
                                connect_tagline := Label{
                                    text: "Connect to a team server"
                                    draw_text.color: Cmuted
                                    draw_text.text_style: theme.font_regular{font_size: 12}
                                }
                            }
                            View{width: Fill height: 1 draw_bg.color: Cborder}
                            // Form body. Inputs use a filled style (bg deeper than
                            // the card, 1px border, magenta focus border) — the VS
                            // Code / One Dark input look confirmed in the mockup.
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 20.0 bottom: 26.0 left: 30.0 right: 30.0}
                                flow: Down spacing: 16.0

                                // Server URL — host + port merged into one field
                                // (simpler than the old two-column HOST/PORT row).
                                View{
                                    width: Fill height: Fit flow: Down spacing: 5.0
                                    url_label := Label{text: "Server URL" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
                                    url_input := TextInput{
                                        width: Fill height: 30
                                        padding: Inset{left: 12.0 right: 12.0}
                                        text: "http://127.0.0.1:8443"
                                        empty_text: "http://host:port"
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Cbg
                                        draw_bg.color_focus: Cbg
                                        draw_bg.border_color: Cborder
                                        draw_bg.border_color_focus: Caccent
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                }
                                View{
                                    width: Fill height: Fit flow: Down spacing: 5.0
                                    alias_label := Label{text: "Operator" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
                                    alias_input := TextInput{
                                        width: Fill height: 30
                                        padding: Inset{left: 12.0 right: 12.0}
                                        text: "operator"
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Cbg
                                        draw_bg.color_focus: Cbg
                                        draw_bg.border_color: Cborder
                                        draw_bg.border_color_focus: Caccent
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                }
                                // Password = API bearer token. Flows into
                                // Cmd::Connect::password; the worker attaches it
                                // as `Authorization: Bearer`. Empty = no token
                                // (local dev server without NYX_TOKEN).
                                View{
                                    width: Fill height: Fit flow: Down spacing: 5.0
                                    pass_label := Label{text: "Password (API Token)" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
                                    pass_input := TextInput{
                                        is_password: true
                                        width: Fill height: 30
                                        padding: Inset{left: 12.0 right: 12.0}
                                        text: ""
                                        empty_text: "team server token (leave empty if none)"
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Cbg
                                        draw_bg.color_focus: Cbg
                                        draw_bg.border_color: Cborder
                                        draw_bg.border_color_focus: Caccent
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                }
                                connect_status := Label{
                                    text: ""
                                    draw_text.color: Cdanger
                                    draw_text.text_style: theme.font_code{font_size: 11}
                                }
                                // Buttons row: theme toggle (left) + Connect (right).
                                View{
                                    width: Fill height: Fit
                                    flow: Right spacing: 8.0
                                    align: Align{y: 0.5}
                                    dialog_theme_btn := Button{
                                        text: "Light Mode"
                                        width: 90 height: 30
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Csecond
                                        draw_text.text_style: theme.font_regular{font_size: 12}
                                    }
                                    View{width: Fill height: 1}
                                    dialog_connect_btn := Button{
                                        text: "Connect"
                                        width: 110 height: 30
                                        draw_bg.color: Caccent
                                        draw_bg.color_hover: Cacchov
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cbg
                                        draw_text.text_style: theme.font_bold{font_size: 12}
                                    }
                                }
                                connect_footer := Label{
                                    text: "Authorized use only · all activity is logged"
                                    draw_text.color: Cmuted
                                    draw_text.text_style: theme.font_regular{font_size: 9}
                                }
                            }
                        }
                    }

                    // ── main console (hidden until connected) ──────────────
                    main_view := View{
                        width: Fill height: Fill
                        visible: false
                        flow: Down spacing: 0

                    // ── connection bar ─────────────────────────────────────
                    conn_bar := SolidView{
                        width: Fill height: 46
                        padding: Inset{left: 16.0 right: 16.0}
                        flow: Right spacing: 12.0
                        align: Align{y: 0.5}
                        draw_bg.color: Cpanel

                        Label{
                            text: "NYX"
                            draw_text.color: Caccent
                            draw_text.text_style: theme.font_bold{font_size: 16}
                        }
                        div_brand := View{width: 1 height: 20 draw_bg.color: Cborder}
                        server_input := TextInput{
                            width: 360 height: 30
                            padding: Inset{left: 10.0 right: 10.0}
                            text: "http://127.0.0.1:8443"
                            empty_text: "team server URL"
                            draw_bg.color: Cbg
                            draw_bg.color_hover: Cbg
                            draw_bg.color_focus: Cbg
                            draw_bg.border_color: Cborder
                            draw_bg.border_color_focus: Caccent
                            draw_bg.border_radius: Cradius_s
                            draw_text.color: Cprimary
                            draw_text.color_hover: Cprimary
                            draw_text.color_focus: Cprimary
                            draw_text.color_empty: Cmuted
                            draw_text.text_style: theme.font_code{font_size: 12}
                            draw_cursor.color: Caccent
                        }
                        bar_connect_btn := Button{
                            text: "Connect"
                            width: 92 height: 30
                            draw_bg.color: Caccent
                            draw_bg.color_hover: Cacchov
                            draw_bg.border_radius: Cradius
                            draw_text.color: #ffffff
                            draw_text.text_style: theme.font_bold{font_size: 12}
                        }
                        // Circular status indicator (border_radius = half size).
                        status_dot := View{
                            width: 10 height: 10
                            flow: Overlay
                            align: Align{x: 0.0 y: 0.5}
                            dot_on := View{
                                width: 8 height: 8
                                draw_bg.color: Csuccess
                                draw_bg.border_radius: 4.0
                                visible: false
                            }
                            dot_off := View{
                                width: 8 height: 8
                                draw_bg.color: Cdanger
                                draw_bg.border_radius: 4.0
                            }
                        }
                        status_text := Label{
                            text: "Disconnected"
                            draw_text.color: Cdanger
                            draw_text.text_style: theme.font_regular{font_size: 12}
                        }
                        // Spacer to push theme button to far right
                        View{width: Fill height: 1}
                        theme_btn := Button{
                            text: "Dark Mode"
                            width: 96 height: 30
                            draw_bg.color: Cbar
                            draw_bg.color_hover: Crowhov
                            draw_bg.border_radius: Cradius
                            draw_text.color: Csecond
                            draw_text.text_style: theme.font_regular{font_size: 12}
                        }
                    }
                    // hairline under connection bar
                    div_conn_bar := View{width: Fill height: 1 draw_bg.color: Cborder}

                    // ── main body: sessions | center ───────────────────────
                    View{
                        width: Fill height: Fill
                        flow: Right spacing: 0

                        left_panel := View{
                            width: 480 height: Fill
                            flow: Down spacing: 0
                            draw_bg.color: Cpanel
                            sessions_header := View{
                                width: Fill height: 32
                                padding: Inset{left: 14.0 right: 14.0}
                                flow: Right spacing: 8.0
                                align: Align{y: 0.5}
                                draw_bg.color: Cbar
                                sessions_header_stripe := View{width: 3 height: 14 draw_bg.color: Caccent}
                                sessions_header_title := Label{text: "SESSIONS" draw_text.color: Cprimary draw_text.text_style: theme.font_bold{font_size: 11}}
                            }
                            session_list := mod.widgets.SessionList{}
                        }
                        // vertical hairline between sessions and center
                        div_left_center := View{width: 1 height: Fill draw_bg.color: Cborder}

                        center_panel := View{
                            width: Fill height: Fill
                            flow: Down spacing: 0
                            draw_bg.color: Cbg

                            // ── tab bar ────────────────────────────────────
                            tab_bar := View{
                                width: Fill height: 30
                                padding: Inset{left: 6.0}
                                flow: Right spacing: 0
                                align: Align{y: 0.5}
                                draw_bg.color: Cbar

                                console_tab := View{
                                    flow: Down width: 90 height: Fill
                                    tab_console := Button{
                                        text: "Console"
                                        width: Fill height: 27
                                        draw_bg.color: Cbar
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.color_down: Crowhov
                                        draw_bg.border_size: 0.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Caccent
                                        draw_text.text_style: theme.font_bold{font_size: 11}
                                    }
                                    line_console := View{
                                        width: Fill height: 3
                                        draw_bg.color: Caccent
                                        visible: true
                                    }
                                }
                                bof_tab := View{
                                    flow: Down width: 64 height: Fill
                                    tab_bof := Button{
                                        text: "BOF"
                                        width: Fill height: 27
                                        draw_bg.color: Cbar
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.color_down: Crowhov
                                        draw_bg.border_size: 0.0
                                        draw_text.color: Cmuted
                                        draw_text.color_hover: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 11}
                                    }
                                    line_bof := View{
                                        width: Fill height: 3
                                        draw_bg.color: Caccent
                                        visible: false
                                    }
                                }
                                files_tab := View{
                                    flow: Down width: 64 height: Fill
                                    tab_files := Button{
                                        text: "Files"
                                        width: Fill height: 27
                                        draw_bg.color: Cbar
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.color_down: Crowhov
                                        draw_bg.border_size: 0.0
                                        draw_text.color: Cmuted
                                        draw_text.color_hover: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 11}
                                    }
                                    line_files := View{
                                        width: Fill height: 3
                                        draw_bg.color: Caccent
                                        visible: false
                                    }
                                }
                                procs_tab := View{
                                    flow: Down width: 96 height: Fill
                                    tab_procs := Button{
                                        text: "Processes"
                                        width: Fill height: 27
                                        draw_bg.color: Cbar
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.color_down: Crowhov
                                        draw_bg.border_size: 0.0
                                        draw_text.color: Cmuted
                                        draw_text.color_hover: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 11}
                                    }
                                    line_procs := View{
                                        width: Fill height: 3
                                        draw_bg.color: Caccent
                                        visible: false
                                    }
                                }
                                creds_tab := View{
                                    flow: Down width: 104 height: Fill
                                    tab_creds := Button{
                                        text: "Credentials"
                                        width: Fill height: 27
                                        draw_bg.color: Cbar
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.color_down: Crowhov
                                        draw_bg.border_size: 0.0
                                        draw_text.color: Cmuted
                                        draw_text.color_hover: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 11}
                                    }
                                    line_creds := View{
                                        width: Fill height: 3
                                        draw_bg.color: Caccent
                                        visible: false
                                    }
                                }
                            }
                            // hairline under tab bar
                            div_tab_bar := View{width: Fill height: 1 draw_bg.color: Cborder}

                            // ── tab bodies (toggled via set_visible) ───────
                            pane_console := View{
                                width: Fill height: Fill
                                align: Center flow: Down spacing: theme.space_2
                                center_text := Label{
                                    text: "Select an active beacon"
                                    draw_text.color: Cmuted
                                    draw_text.text_style: theme.font_bold{font_size: 14}
                                }
                                center_sub := Label{
                                    text: "Interactive console output will be directed here once selected"
                                    draw_text.color: Cmuted
                                    draw_text.text_style: theme.font_regular{font_size: 11}
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
                    div_center_log := View{width: Fill height: 1 draw_bg.color: Cborder}
                    log_panel := View{
                        width: Fill height: 140
                        flow: Down spacing: 0
                        draw_bg.color: Cpanel
                        log_header := View{
                            width: Fill height: 30
                            padding: Inset{left: 14.0 right: 14.0}
                            flow: Right spacing: 8.0
                            align: Align{y: 0.5}
                            draw_bg.color: Cbar
                            log_header_stripe := View{width: 3 height: 14 draw_bg.color: Caccent}
                            log_header_title := Label{text: "EVENT LOG" draw_text.color: Cprimary draw_text.text_style: theme.font_bold{font_size: 11}}
                        }
                        log_list := mod.widgets.LogList{}
                    }
                    } // close main_view
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
    #[rust]
    is_dark: bool,
    #[rust]
    has_connected: bool,
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
        if snap.connected {
            self.has_connected = true;
        }
        // If we have ever connected successfully, we remain in the console view.
        // If we haven't connected yet, keep showing the connect dialog.
        self.ui.view(cx, ids!(connect_view)).set_visible(cx, !self.has_connected);
        self.ui.view(cx, ids!(main_view)).set_visible(cx, self.has_connected);
        if !snap.connected && !self.has_connected {
            // Show the most recent error line in the dialog (e.g. connection refused).
            let last_err = LOG_LINES.read().unwrap().last().cloned();
            if let Some(e) = last_err {
                self.ui.label(cx, ids!(connect_status)).set_text(cx, &e);
            }
        }
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
            .set_text(cx, if connected { "Connected" } else { "Disconnected" });
        // Color the status word to match the dot so the state reads at a glance.
        let p = Palette::current();
        let st_color = if connected { p.success } else { p.danger };
        let mut st_lbl = self.ui.label(cx, ids!(status_text));
        script_apply_eval!(cx, st_lbl, {
            draw_text +: { color: #(st_color) }
        });
    }

    /// Repaint every static (non-virtualized) surface for the current theme.
    ///
    /// Colors come from the single [`Palette`] source of truth (`theme.rs`) —
    /// the same ramp the per-row `draw_walk` functions use — so the Light/Dark
    /// toggle stays consistent everywhere. Virtualized list rows repaint
    /// themselves each frame in their own `draw_walk`, so they are NOT touched
    /// here; only fixed surfaces (bars, panels, dialog, inputs, buttons,
    /// dividers) need a one-shot repaint on toggle.
    fn apply_theme(&self, cx: &mut Cx) {
        let is_dark = self.is_dark;
        let p = Palette::current();
        let cbg = p.bg;
        let cbar = p.bar;
        let cpanel = p.panel;
        let celev = p.elev;
        let cborder = p.border;
        let cprimary = p.primary;
        let cmuted = p.muted;
        let caccent = p.accent;
        let cacchov = p.acchov;
        let crowhov = p.rowhov;

        // 1. MainWindow clear_color
        let mut w = self.ui.window(cx, ids!(main_window));
        script_apply_eval!(cx, w, {
            pass +: { clear_color: #(cbg) }
        });

        // 2. Dialog: backdrop, card, logo box.
        let mut cv = self.ui.view(cx, ids!(connect_view));
        script_apply_eval!(cx, cv, {
            draw_bg +: { color: #(cbg) }
        });
        let mut cc = self.ui.view(cx, ids!(connect_card));
        script_apply_eval!(cx, cc, {
            draw_bg +: { color: #(celev), border_color: #(cborder) }
        });
        // Logo box (filled with accent) + its "N" letter (drawn in bg color so
        // it inverts against the magenta).
        let mut lb = self.ui.view(cx, ids!(logo_box));
        script_apply_eval!(cx, lb, {
            draw_bg +: { color: #(caccent) }
        });
        let mut ll = self.ui.label(cx, ids!(logo_letter));
        script_apply_eval!(cx, ll, {
            draw_text +: { color: #(cbg) }
        });

        // 3. Text inputs (dialog fields + connection-bar server field).
        let inputs = [
            ids!(url_input),
            ids!(pass_input),
            ids!(alias_input),
            ids!(server_input),
        ];
        for path in inputs {
            let mut inp = self.ui.text_input(cx, path);
            script_apply_eval!(cx, inp, {
                draw_bg +: { color: #(cbg), border_color: #(cborder), border_color_focus: #(caccent) }
                draw_text +: { color: #(cprimary), color_empty: #(cmuted) }
                draw_cursor +: { color: #(caccent) }
            });
        }

        // 4. Buttons — accent primary (Connect, dark text), bar-colored secondaries.
        let buttons = [
            (ids!(dialog_connect_btn), caccent, cacchov, cbg),
            (ids!(bar_connect_btn), caccent, cacchov, cbg),
            (ids!(theme_btn), cbar, crowhov, cprimary),
            (ids!(dialog_theme_btn), cbg, crowhov, cmuted),
        ];
        for (path, bg, bg_hov, fg) in buttons {
            let mut btn = self.ui.button(cx, path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(bg), color_hover: #(bg_hov) }
                draw_text +: { color: #(fg) }
            });
        }

        let mode_label = if is_dark { "Light Mode" } else { "Dark Mode" };
        self.ui.button(cx, ids!(dialog_theme_btn)).set_text(cx, mode_label);
        self.ui.button(cx, ids!(theme_btn)).set_text(cx, mode_label);

        // 5. Dialog text: error status, wordmark/tagline/title, field labels.
        let mut cs_lbl = self.ui.label(cx, ids!(connect_status));
        script_apply_eval!(cx, cs_lbl, {
            draw_text +: { color: #(p.danger) }
        });
        let dialog_labels = [
            (ids!(nyx_logo), cprimary),
            (ids!(connect_tagline), cmuted),
            (ids!(url_label), cmuted),
            (ids!(alias_label), cmuted),
            (ids!(pass_label), cmuted),
            (ids!(connect_footer), cmuted),
        ];
        for (path, color) in dialog_labels {
            let mut lbl = self.ui.label(cx, path);
            script_apply_eval!(cx, lbl, {
                draw_text +: { color: #(color) }
            });
        }

        // 6. Connection bar.
        let mut conn_b = self.ui.view(cx, ids!(conn_bar));
        script_apply_eval!(cx, conn_b, {
            draw_bg +: { color: #(cpanel) }
        });

        // 7. Split panels & their section headers.
        let mut lp = self.ui.view(cx, ids!(left_panel));
        script_apply_eval!(cx, lp, {
            draw_bg +: { color: #(cpanel) }
        });
        let mut sh = self.ui.view(cx, ids!(sessions_header));
        script_apply_eval!(cx, sh, {
            draw_bg +: { color: #(cbar) }
        });
        let mut shs = self.ui.view(cx, ids!(sessions_header_stripe));
        script_apply_eval!(cx, shs, {
            draw_bg +: { color: #(caccent) }
        });
        let mut sht = self.ui.label(cx, ids!(sessions_header_title));
        script_apply_eval!(cx, sht, {
            draw_text +: { color: #(cprimary) }
        });

        let mut cp = self.ui.view(cx, ids!(center_panel));
        script_apply_eval!(cx, cp, {
            draw_bg +: { color: #(cbg) }
        });
        let mut tb = self.ui.view(cx, ids!(tab_bar));
        script_apply_eval!(cx, tb, {
            draw_bg +: { color: #(cbar) }
        });

        // Tab buttons + their active underlines.
        let tabs = [
            (ids!(tab_console), ids!(line_console)),
            (ids!(tab_bof), ids!(line_bof)),
            (ids!(tab_files), ids!(line_files)),
            (ids!(tab_procs), ids!(line_procs)),
            (ids!(tab_creds), ids!(line_creds)),
        ];
        for (btn_path, line_path) in tabs {
            let mut btn = self.ui.button(cx, btn_path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(cbar), color_hover: #(crowhov), color_down: #(crowhov) }
                draw_text +: { color: #(cprimary), color_hover: #(caccent) }
            });
            let mut line = self.ui.view(cx, line_path);
            script_apply_eval!(cx, line, {
                draw_bg +: { color: #(caccent) }
            });
        }

        // Center console placeholder text.
        let mut ctxt = self.ui.label(cx, ids!(center_text));
        script_apply_eval!(cx, ctxt, {
            draw_text +: { color: #(cprimary) }
        });
        let mut csub = self.ui.label(cx, ids!(center_sub));
        script_apply_eval!(cx, csub, {
            draw_text +: { color: #(cmuted) }
        });

        // 8. Event log panel + its section header.
        let mut log_p = self.ui.view(cx, ids!(log_panel));
        script_apply_eval!(cx, log_p, {
            draw_bg +: { color: #(cpanel) }
        });
        let mut log_h = self.ui.view(cx, ids!(log_header));
        script_apply_eval!(cx, log_h, {
            draw_bg +: { color: #(cbar) }
        });
        let mut log_hs = self.ui.view(cx, ids!(log_header_stripe));
        script_apply_eval!(cx, log_hs, {
            draw_bg +: { color: #(caccent) }
        });
        let mut log_ht = self.ui.label(cx, ids!(log_header_title));
        script_apply_eval!(cx, log_ht, {
            draw_text +: { color: #(cprimary) }
        });

        // 9. Hairlines / dividers (includes the brand divider in the conn bar).
        let dividers = [
            ids!(div_conn_bar),
            ids!(div_brand),
            ids!(div_left_center),
            ids!(div_tab_bar),
            ids!(div_center_log),
        ];
        for path in dividers {
            let mut div = self.ui.view(cx, path);
            script_apply_eval!(cx, div, {
                draw_bg +: { color: #(cborder) }
            });
        }
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
        // Toggle the visibility of active tab gold underlines.
        let lines = [
            (Tab::Console, ids!(line_console)),
            (Tab::Bof, ids!(line_bof)),
            (Tab::Files, ids!(line_files)),
            (Tab::Procs, ids!(line_procs)),
            (Tab::Creds, ids!(line_creds)),
        ];
        for (t, id) in lines {
            self.ui.view(cx, id).set_visible(cx, t == tab);
        }
        self.ui.redraw(cx);
    }
}

impl MatchEvent for App {
    fn handle_startup(&mut self, cx: &mut Cx) {
        self.is_dark = true;
        IS_DARK.store(true, std::sync::atomic::Ordering::Relaxed);
        self.set_status(cx, false);
        self.apply_theme(cx);
        self.ui.redraw(cx);
    }

    fn handle_actions(&mut self, cx: &mut Cx, actions: &Actions) {
        // Theme button click
        if self.ui.button(cx, ids!(theme_btn)).clicked(actions)
            || self.ui.button(cx, ids!(dialog_theme_btn)).clicked(actions)
        {
            self.is_dark = !self.is_dark;
            IS_DARK.store(self.is_dark, std::sync::atomic::Ordering::Relaxed);
            self.apply_theme(cx);
            self.ui.redraw(cx);
        }

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

        // ── Connect dialog (the dedicated connect window) ────────────────
        // Connect button OR Enter in any connect-dialog field.
        let dlg_connect = self.ui.button(cx, ids!(dialog_connect_btn)).clicked(actions);
        let dlg_enter = self.ui.text_input(cx, ids!(url_input)).returned(actions).is_some()
            || self.ui.text_input(cx, ids!(alias_input)).returned(actions).is_some()
            || self.ui.text_input(cx, ids!(pass_input)).returned(actions).is_some();

        let bar_connect = self.ui.button(cx, ids!(bar_connect_btn)).clicked(actions);

        if dlg_connect || dlg_enter || bar_connect {
            self.ensure_bridge();
            if let Some(b) = &self.bridge {
                let (url, password) = if bar_connect {
                    (self.ui.text_input(cx, ids!(server_input)).text(), None)
                } else {
                    let raw = self.ui.text_input(cx, ids!(url_input)).text();
                    let pw = self.ui.text_input(cx, ids!(pass_input)).text();
                    let pw = if pw.trim().is_empty() { None } else { Some(pw) };
                    (raw, pw)
                };
                let _ = b.from_ui.send(Cmd::Connect {
                    server: url.trim().to_string(),
                    password,
                });
                if !bar_connect {
                    self.ui.label(cx, ids!(connect_status)).set_text(cx, "Connecting…");
                }
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
                SELECTED_SESSION.store(item_id, std::sync::atomic::Ordering::Relaxed);
                let sessions = SESSIONS.read().unwrap();
                let s = sessions.get(item_id);
                let text = match s {
                    Some(s) => format!("● {} @ {}   (ID {:.8})", s.hostname, s.username, s.id),
                    None => "Select an active beacon".to_string(),
                };
                let sub = if s.is_some() {
                    "Interactive console online".to_string()
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
                    let sel = SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
                    list.set_item_range(cx, 0, sessions.len());
                    while let Some(item_id) = list.next_visible_item(cx) {
                        let Some(s) = sessions.get(item_id) else { continue };
                        // Selected row uses the ItemSel template (blue bg);
                        // others use Item. Verified per-row-id approach.
                        let item = list.item(cx, item_id, if item_id == sel { id!(ItemSel) } else { id!(Item) });

                        // Repaint the row from the single Palette source so the
                        // Light/Dark toggle matches apply_theme exactly.
                        let p = Palette::current();
                        let row_color = if item_id == sel { p.rowsel } else { p.row };
                        let mut row_item = item.clone();
                        script_apply_eval!(cx, row_item, {
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
