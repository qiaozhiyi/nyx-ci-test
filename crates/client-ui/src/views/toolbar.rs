//! The single consolidated toolbar + the collapsible reconnect bar.
//!
//! 2026-07-17 refactor: the fake menu bar (NYX/View/Attacks/Reporting/Help —
//! its click handler was a literal `redraw` no-op) is gone; the toolbar is now
//! ONE row: text view-tabs on the left (active tab = accent background, the
//! one violet signal), connection status + theme toggle on the right.
//!
//! The reconnect bar (`conn_bar`) keeps the real quick-reconnect control
//! (server URL + Connect). `set_status` hides it while connected, so in the
//! steady state the header is exactly one row.

use makepad_widgets::*;

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*
    use mod.nyx.*

    // ── view-tab button styles ──────────────────────────────────────────────
    // Active tab: solid accent fill + dark text — the single violet signal for
    // "you are here" (button bg is the reliably-repainted surface in this
    // Makepad rev; a separate underline View doesn't paint reliably as a
    // Button sibling). Inactive: transparent fill, secondary text, row-hover
    // fill on hover. set_top_pane()/apply_theme() re-apply exactly these rules.
    let TopTabActive = Button{
        width: Fit height: 24
        padding: Inset{left: 10.0 right: 10.0 top: 2.0 bottom: 2.0}
        margin: Inset{left: 2.0 right: 2.0}
        draw_bg.color: Caccent
        draw_bg.color_hover: Cacchov
        draw_bg.color_down: Cacchov
        draw_bg.border_size: 0.0
        draw_bg.border_radius: Cradius
        draw_text.color: Cbg
        draw_text.color_hover: Cbg
        draw_text.color_down: Cbg
        draw_text.text_style: theme.font_bold{font_size: 11}
    }
    let TopTab = Button{
        width: Fit height: 24
        padding: Inset{left: 10.0 right: 10.0 top: 2.0 bottom: 2.0}
        margin: Inset{left: 2.0 right: 2.0}
        draw_bg.color: #x00000000
        draw_bg.color_hover: Crowhov
        draw_bg.color_down: Crowhov
        draw_bg.border_size: 0.0
        draw_bg.border_radius: Cradius
        draw_text.color: Csecond
        draw_text.color_hover: Cprimary
        draw_text.color_down: Cprimary
        draw_text.text_style: theme.font_bold{font_size: 11}
    }

    mod.nyx.ToolBar = View{
        show_bg: true
        width: Fill height: 34
        flow: Right spacing: 0
        padding: Inset{left: 10.0 right: 10.0}
        align: Align{y: 0.5}
        draw_bg.color: Cpanel

        tb_brand := Label{
            text: "NYX"
            margin: Inset{right: 10.0}
            draw_text.color: Caccent
            draw_text.text_style: theme.font_bold{font_size: 13}
        }
        tb_brand_div := View{width: 1 height: 16 margin: Inset{right: 8.0} draw_bg.color: Cborder}

        // Text view-tabs (emoji icons removed 2026-07-17 — text carries it).
        btn_table := TopTabActive{text: "Sessions"}
        btn_graph := TopTab{text: "Graph"}
        btn_files := TopTab{text: "Files"}
        btn_procs := TopTab{text: "Processes"}
        btn_creds := TopTab{text: "Creds"}
        btn_event_log := TopTab{text: "Event Log"}

        View{width: Fill height: 1}

        // Live connection status — always visible (it used to hide together
        // with the reconnect bar, and the dot was never even toggled: a red
        // dot at all times. set_status now flips dot_on/dot_off too.)
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
            margin: Inset{left: 2.0 right: 4.0}
            draw_text.color: Cdanger
            draw_text.text_style: theme.font_regular{font_size: 11}
        }
        // Theme toggle — text label, not an emoji glyph (2026-07-17).
        main_btn_theme := Button{
            text: "Theme: Dark"
            width: Fit height: 24
            padding: Inset{left: 10.0 right: 10.0}
            margin: Inset{left: 6.0}
            draw_bg.color: #x00000000
            draw_bg.color_hover: Crowhov
            draw_bg.color_down: Crowhov
            draw_bg.border_color: Cborder
            draw_bg.border_size: 1.0
            draw_bg.border_radius: Cradius
            draw_text.color: Cmuted
            draw_text.color_hover: Cprimary
            draw_text.text_style: theme.font_code{font_size: 11}
        }
    }

    // ── reconnect bar (visible only while disconnected) ─────────────────────
    mod.nyx.ConnBar = View{
        show_bg: true
        width: Fill height: 46
        padding: Inset{left: 16.0 right: 16.0}
        flow: Right spacing: 12.0
        align: Align{y: 0.5}
        draw_bg.color: Cbar

        server_label := Label{
            text: "Server"
            draw_text.color: Cmuted
            draw_text.text_style: theme.font_bold{font_size: 11}
        }
        server_input := TextInput{
            width: 360 height: 30
            label_align: Align{y: 0.5}
            padding: Inset{left: 10.0, right: 10.0, top: 4.0, bottom: 4.0}
            text: "http://127.0.0.1:8443"
            empty_text: "team server URL"
            draw_bg.color: Cinput
            draw_bg.color_hover: Cinput
            draw_bg.color_focus: Cinput
            draw_bg.color_empty: Cinput
            draw_bg.border_color: Cinput_b
            draw_bg.border_color_hover: Cinput_b
            draw_bg.border_color_focus: Caccent
            draw_bg.border_color_empty: Cinput_b
            draw_bg.border_color_2: Cinput_b
            draw_bg.border_color_2_hover: Cinput_b
            draw_bg.border_color_2_focus: Caccent
            draw_bg.border_color_2_empty: Cinput_b
            draw_bg.border_size: 1.0
            draw_bg.border_radius: Cradius
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
            draw_text.color: Cbg
            draw_text.text_style: theme.font_bold{font_size: 12}
        }
    }
}
