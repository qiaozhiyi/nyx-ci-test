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
mod parse;
pub mod theme;
pub mod widgets;

use crate::theme::Palette;

use crate::widgets::{
    bof_panel::{BofEntry, BofPanel, BofStatus, BOFS},
    console_list::ConsoleList,
    cred_table::CredTable,
    file_tree::FileTree,
    process_table::ProcessTable,
    session_graph::SessionGraph,
};

use std::sync::{LazyLock, RwLock};

use bridge::{Bridge, Cmd, SessionView, Snapshot};

// ── shared UI state, read by the list widgets during draw ───────────────────
// LazyLock<RwLock<..>> mirrors the `todo` example exactly. Draw is on the UI
// thread and single-threaded, so the write-lock in apply_snapshot() never
// contends in practice; the RwLock is just the documented Makepad idiom.

static SESSIONS: LazyLock<RwLock<Vec<SessionView>>> = LazyLock::new(|| RwLock::new(vec![
    SessionView {
        id: "mock_1".to_string(),
        hostname: "DESKTOP-WIN".to_string(),
        username: "admin".to_string(),
        os: "Windows 11".to_string(),
        arch: 64,
        pid: 1024,
        is_admin: 1,
        ..Default::default()
    },
    SessionView {
        id: "mock_2".to_string(),
        hostname: "MacBook-Pro".to_string(),
        username: "qiaozhiyi".to_string(),
        os: "Mac OS X".to_string(),
        arch: 64,
        pid: 3001,
        is_admin: 0,
        ..Default::default()
    },
    SessionView {
        id: "mock_3".to_string(),
        hostname: "ubuntu-server".to_string(),
        username: "root".to_string(),
        os: "Linux".to_string(),
        arch: 64,
        pid: 1,
        is_admin: 1,
        ..Default::default()
    }
]));
static LOG_LINES: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));
pub static CONSOLE: LazyLock<RwLock<std::collections::HashMap<String, Vec<String>>>> = LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));
pub static IS_DARK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Index of the currently-selected session row, or usize::MAX for none.
/// SessionList::draw_walk reads this to tint the selected row's background
/// (Crowsel) — the only way to give per-row selection feedback through a
/// virtualized PortalList (the App can't reach inside individual rows).
static SELECTED_SESSION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

app_main!(App);

script_mod! {
    use mod.prelude.widgets.*
    use mod.widgets.*

    // ── Cobalt Industrial palette ──────────────────────────────────────────
    let Cbg       = #xD0D0D0  // app background — deepest surface
    let Cinput    = #xFFFFFF  // input fill
    let Cinput_b  = #xA0A0A0  // visible input border
    let Cbar      = #xE0E0E0  // recessed secondary bars / tab bar
    let Cpanel    = #xF0F0F0  // side panels + event-log shell
    let Crow      = #xFFFFFF  // table/data-row base
    let Crowhov   = #xE8F0FA  // row hover
    let Crowsel   = #x3B72AB  // row selected (cobalt blue)
    let Celev     = #xEAEAEA  // brightest surface — column headers / dialog card
    let Cborder   = #xA0A0A0  // hairline dividers
    let Cprimary  = #x000000  // primary text
    let Csecond   = #x333333  // secondary text
    let Cmuted    = #x666666  // muted text / column labels
    let Caccent   = #x3B72AB  // Cobalt blue accent
    let Cacchov   = #x5B9BD5  // accent hover
    let Csuccess  = #x008000  // success / online (teal)
    let Cdanger   = #xD13438  // danger / alert
    let Cwarn     = #xE38B00  // warning / pending / secrets
    let Cinfo     = #x005A9C  // info / command keyword
    let Cunder    = #x3B72AB  // active-tab underline
    let Cradius   = 6.0       // unified corner radius (cards / buttons / inputs)
    let Cradius_s = 3.0       // small radius (tags / badges)
    // Shared layout metrics so column headers and data rows stay perfectly
    // aligned: both reference these instead of re-typing the same numbers.
    let Cpad      = 14.0      // table row / header horizontal inset
    let Cgap      = 16.0      // column gap inside rows / headers

    // ── animated network-node background (glassmorphism scene) ──────────────
    // Pure-DSL shader View (the GlassPanel precedent — no Rust struct). Draws a
    // vertical 2-stop gradient + a drifting grid of glowing nodes + faint
    // connecting lines, all in one pixel fn. The drift is driven by
    // self.draw_pass.time so it animates every frame with no app-side code.
    // GaussRoundedView (the glass card) blurs whatever THIS renders behind it,
    // so this is what makes the frosted glass actually read as frosted.
    let NetworkBg = View{
        show_bg: true
        draw_bg +: {
            grad_top: instance(#x111111)
            grad_bot: instance(#x050505)
            node_color: instance(#x666666)
            line_color: instance(#x007ACC)

            pixel: fn() {
                // Vertical 2-stop gradient as the base.
                let bg = self.grad_top.rgb.mix(self.grad_bot.rgb, self.pos.y)

                // Drifting node grid. Cell size in px; drift over time.
                let cell = 90.0
                let drift = vec2(self.draw_pass.time * 4.0, self.draw_pass.time * 2.5)
                let p = self.pos * self.rect_size + drift
                let gx = floor(p.x / cell)
                let gy = floor(p.y / cell)

                // Per-cell pseudo-jitter from gx/gy (deterministic per cell).
                let jx = Math.random_2d(vec2(gx * 12.9 + gy * 78.2, 1.0))
                let jy = Math.random_2d(vec2(gx * 4.1 + gy * 91.7, 2.0))
                let cx = (gx + 0.5) * cell - drift.x + (jx - 0.5) * cell * 0.5
                let cy = (gy + 0.5) * cell - drift.y + (jy - 0.5) * cell * 0.5

                let sdf = Sdf2d.viewport(self.pos * self.rect_size)

                // Glowing node dot (additive).
                sdf.circle(cx, cy, 2.0)
                sdf.glow_keep(vec4(self.node_color.rgb, 0.5), 6.0)

                // Connecting line to the right-neighbor node.
                let cx2 = (gx + 1.5) * cell - drift.x + (Math.random_2d(vec2((gx + 1.0) * 12.9 + gy * 78.2, 1.0)) - 0.5) * cell * 0.5
                let cy2 = (gy + 0.5) * cell - drift.y + (Math.random_2d(vec2((gx + 1.0) * 4.1 + gy * 91.7, 2.0)) - 0.5) * cell * 0.5
                sdf.move_to(cx, cy)
                sdf.line_to(cx2, cy2)
                sdf.stroke(vec4(self.line_color.rgb, 0.18), 1.0)

                // Composite shader layer over the gradient base.
                let layer = sdf.result
                return vec4(bg * (1.0 - layer.a) + layer.rgb, 1.0)
            }
        }
    }

    // ── glass card (real frosted-glass surface) ─────────────────────────────
    // GaussRoundedView wrapper tuned for the login dialog: translucent tint +
    // real backdrop blur + magenta neon border + soft gaussian shadow. The
    // instance vs uniform split: properties apply_theme recolors per-theme
    // (tint/border/shadow/fallback) = instance; static knobs (blur level,
    // surface alpha, radii) = uniform.
    let GlassCard = GaussRoundedView{
        width: Fill height: Fill
        flow: Down
        draw_bg +: {
            tint_color: instance(Celev)
            tint_alpha: uniform(1.0)
            surface_alpha: uniform(1.0)
            border_color: instance(#x007ACC)
            border_alpha: instance(0.0)
            border_width: instance(0.0)
            corner_radius: instance(0.0)
            blur_level: uniform(0.0)
            shadow_color: instance(#x00000000)
            shadow_radius: uniform(0.0)
            shadow_offset: uniform(vec2(0.0, 0.0))
            fallback_color: instance(Celev)
        }
    }

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
                draw_text.text_style: theme.font_bold{font_size: theme.font_size_code}
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
            margin: Inset{top: 29.0}
            draw_bg.color: Cborder
        }
    }

    let EmptySessions = View{
        width: Fill height: Fill
        align: Center flow: Down spacing: 8.0
        Label{text: "No Active Beacons" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 13}}
        Label{text: "Connect to a team server to display beacons" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
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
    mod.widgets.ConsoleListBase = #(ConsoleList::register_widget(vm))
    mod.widgets.ConsoleList = set_type_default() do mod.widgets.ConsoleListBase{
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

    mod.widgets.SessionGraphBase = #(SessionGraph::register_widget(vm))
    mod.widgets.SessionGraph = set_type_default() do mod.widgets.SessionGraphBase{
        width: Fill height: Fill
        scroll_bars: mod.widgets.ScrollBars {show_scroll_x: false, show_scroll_y: true}
        Node := View {
            width: 120 height: 90
            flow: Down spacing: 4.0
            align: Align{x: 0.5, y: 0.5}
            
            icon_view := View {
                width: 40 height: 40
                align: Align{x: 0.5, y: 0.5}
                os_lbl := Label { text: "" draw_text.color: Cmuted draw_text.text_style: theme.font_bold{font_size: 11} }
            }
            lbl := Label { text: "" draw_text.color: Cprimary draw_text.text_style: theme.font_bold{font_size: 12} }
            sub_lbl := Label { text: "" draw_text.color: Csecond draw_text.text_style: theme.font_regular{font_size: 10} }
        }
        
        HLine := View { show_bg: true width: 0 height: 2 draw_bg.color: Caccent }
        VLine := View { show_bg: true width: 2 height: 0 draw_bg.color: Caccent }
    }

    let app = startup() do #(App::script_component(vm)){
        ui: Root{
            // No `on_startup` render() call: our dynamic content is driven by
            main_window := Window{
                show_caption_bar: true
                window.inner_size: vec2(360, 480)
                pass.clear_color: Cpanel
                body +: {
                    width: Fill height: Fill
                    // hidden; handle_signal flips them once the bridge reports
                    // connected:true. Mirrors CS's "connect dialog first" flow.
                    flow: Down

                    // ── connect dialog (shown until connected) ──────────────
                    // NOTE: connect_view / connect_card / logo_box are plain View,
                    // NOT SolidView. In Makepad 2.0 `self.ui.view()` returns the
                    // wrong widget type for a SolidView, and a `script_apply_eval!`
                    // through it silently writes garbage to draw_bg — which is why
                    // Light mode never recoloured the card in v1. View supports the
                    // same draw_bg.color / border_radius / border_color surface
                    // props AND repaints correctly via apply_theme(). Keep these
                    // three as View.
                    connect_view := SolidView{
                        width: Fill height: Fill
                        padding: Inset{top: 0.0 left: 0.0 right: 0.0}
                        flow: Down spacing: 0
                        draw_bg.color: Cpanel
                        connect_card := View{
                            show_bg: true
                            width: Fill height: Fill
                            flow: Down

                            // Brand header — compact.
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 12.0 bottom: 6.0 left: 20.0 right: 20.0}
                                flow: Down spacing: 2.0
                                View{
                                    width: Fit height: Fit
                                    flow: Right spacing: 8.0
                                    align: Align{y: 0.5}
                                    logo_box := RoundedView{
                                        width: 28 height: 28
                                        draw_bg.color: Caccent
                                        draw_bg.border_radius: 6.0
                                        align: Align{x: 0.5, y: 0.5}
                                        logo_letter := Label{
                                            text: "N"
                                            draw_text.color: Cbg
                                            draw_text.text_style: theme.font_bold{font_size: 14}
                                        }
                                    }
                                    nyx_logo := Label{
                                        text: "Nyx Operator"
                                        draw_text.color: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 16}
                                    }
                                }
                                connect_tagline := Label{
                                    text: "CONNECT TO TEAM SERVER"
                                    draw_text.color: Caccent
                                    draw_text.text_style: theme.font_bold{font_size: 10}
                                }
                            }
                            View{width: Fill height: 1 draw_bg.color: Cborder}
                            // Form body. Inputs BLEND with the card (fill =
                            // elev) — no lighter/darker patch fighting the
                            // surface. The field boundary is carried entirely
                            // by a clearly visible 1px border (GitHub-dark
                            // input pattern). Saturated magenta lights up ONLY
                            // on focus — one signal, not three boxes. Every
                            // earlier attempt to use fill contrast (darker =
                            // grey patch, brighter = floating box) read worse.
                            // Each field is a Down column: label / input / (error
                            // or helper) — inline errors live right under the field
                            // they describe, never stacked at the bottom.
                            fields_view := View{
                                width: Fill height: Fit
                                padding: Inset{top: 6.0 bottom: 2.0 left: 20.0 right: 20.0}
                                flow: Down spacing: 2.0

                                // Server URL — host + port merged into one field.
                                View{
                                    width: Fill height: Fit flow: Down spacing: 1.0
                                    url_label := Label{text: "Server URL" draw_text.color: Csecond draw_text.text_style: theme.font_bold{font_size: 10}}
                                    url_input := TextInput{
                                        width: Fill height: 28
                                        label_align: Align{y: 0.5}
                                        padding: Inset{left: 12.0, right: 12.0, top: 4.0, bottom: 4.0}
                                        text: "http://127.0.0.1:8443"
                                        empty_text: "http://host:port"
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
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                    url_error := Label{
                                        visible: false
                                        text: ""
                                        draw_text.color: Cdanger
                                        draw_text.text_style: theme.font_code{font_size: 10}
                                    }
                                }
                                View{
                                    width: Fill height: Fit flow: Down spacing: 1.0
                                    alias_label := Label{text: "Operator" draw_text.color: Csecond draw_text.text_style: theme.font_bold{font_size: 10}}
                                    alias_input := TextInput{
                                        width: Fill height: 28
                                        label_align: Align{y: 0.5}
                                        padding: Inset{left: 12.0, right: 12.0, top: 4.0, bottom: 4.0}
                                        text: "operator"
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
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                    alias_error := Label{
                                        visible: false
                                        text: ""
                                        draw_text.color: Cdanger
                                        draw_text.text_style: theme.font_code{font_size: 10}
                                    }
                                }
                                View{
                                    width: Fill height: Fit flow: Down spacing: 1.0
                                    pass_label := Label{text: "Password (API Token)" draw_text.color: Csecond draw_text.text_style: theme.font_bold{font_size: 10}}
                                    pass_input := TextInput{
                                        is_password: true
                                        width: Fill height: 28
                                        label_align: Align{y: 0.5}
                                        padding: Inset{left: 12.0, right: 12.0, top: 4.0, bottom: 4.0}
                                        text: ""
                                        empty_text: "Enter Team Server Token"
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
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                    pass_helper := Label{
                                        text: "Leave empty if none"
                                        draw_text.color: Csecond
                                        draw_text.text_style: theme.font_regular{font_size: 11}
                                    }
                                }
                                connect_status := Label{
                                    visible: false
                                    text: ""
                                    draw_text.color: Cdanger
                                    draw_text.text_style: theme.font_code{font_size: 11}
                                }
                            }
                            View{width: Fill height: 1 draw_bg.color: Cborder}
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 6.0 bottom: 8.0 left: 20.0 right: 20.0}
                                flow: Down spacing: 5.0
                                theme_toggle_dialog := View {
                                    width: Fill height: 36
                                    flow: Right spacing: 0
                                    padding: Inset{top: 0 bottom: 0 left: 0 right: 0}
                                    
                                    dialog_btn_theme := Button {
                                        text: "THEME: DARK"
                                        width: Fill height: Fill
                                        draw_bg.color: Cinput
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.border_radius: 6.0
                                        draw_bg.border_color: Cinput_b
                                        draw_bg.border_size: 1.0
                                        draw_text.color: Cprimary
                                        draw_text.text_style: theme.font_code{font_size: 11}
                                    }
                                }
                                dialog_connect_btn := Button{
                                    text: "Connect"
                                    width: Fill height: 36
                                    draw_bg.color: Caccent
                                    draw_bg.color_2: #x0050A0
                                    draw_bg.gradient_fill_horizontal: 1.0
                                    draw_bg.color_2_hover: #xB98BCC
                                    draw_bg.border_radius: 8.0
                                    draw_text.color: Cbg
                                    draw_text.text_style: theme.font_bold{font_size: 13}
                                }
                                connect_footer := Label{
                                    text: "Authorized use only · all activity is logged"
                                    draw_text.color: Csecond
                                    draw_text.text_style: theme.font_regular{font_size: 11}
                                }
                            }
                        }
                    }

                    // ── main console (hidden until connected) ──────────────
                    main_view := SolidView{
                        width: Fill height: Fill
                        visible: false
                        flow: Down spacing: 0
                        draw_bg.color: Cbg

                        menu_bar := View {
                            show_bg: true
                            width: Fill height: 26
                            flow: Right spacing: 4.0
                            padding: Inset { left: 8.0 right: 8.0 }
                            align: Align{y: 0.5}
                            draw_bg.color: Cbar
                            
                            menu_nyx := Button {
                                text: "NYX"
                                draw_bg.color: #x00000000
                                draw_text.color: Cprimary
                                draw_bg.border_size: 0.0
                                draw_text.text_style: theme.font_bold{font_size: 11}
                            }
                            menu_view := Button {
                                text: "View"
                                draw_bg.color: #x00000000
                                draw_text.color: Cprimary
                                draw_bg.border_size: 0.0
                                draw_text.text_style: theme.font_bold{font_size: 11}
                            }
                            menu_attacks := Button {
                                text: "Attacks"
                                draw_bg.color: #x00000000
                                draw_text.color: Cprimary
                                draw_bg.border_size: 0.0
                                draw_text.text_style: theme.font_bold{font_size: 11}
                            }
                            menu_reporting := Button {
                                text: "Reporting"
                                draw_bg.color: #x00000000
                                draw_text.color: Cprimary
                                draw_bg.border_size: 0.0
                                draw_text.text_style: theme.font_bold{font_size: 11}
                            }
                            menu_help := Button {
                                text: "Help"
                                draw_bg.color: #x00000000
                                draw_text.color: Cprimary
                                draw_bg.border_size: 0.0
                                draw_text.text_style: theme.font_bold{font_size: 11}
                            }
                        }
                        
                        div_menu := View { width: Fill height: 1 draw_bg.color: Cborder }

                        tool_bar := View {
                            width: Fill height: 32
                            flow: Right spacing: 6.0
                            padding: Inset { left: 10.0 right: 10.0 }
                            align: Align{y: 0.5}
                            draw_bg.color: Cpanel
                            
                            div_1 := View { width: 1 height: 18 draw_bg.color: Cborder }
                            btn_table := Button { text: "📊 Sessions" draw_bg.color: Cbar width: Fit height: 26 padding: Inset{left: 8.0 right: 8.0 top: 2.0 bottom: 2.0} draw_text.text_style: theme.font_regular{font_size: 11} }
                            btn_graph := Button { text: "🕸️ Graph" draw_bg.color: Cbar width: Fit height: 26 padding: Inset{left: 8.0 right: 8.0 top: 2.0 bottom: 2.0} draw_text.text_style: theme.font_regular{font_size: 11} }
                            div_2 := View { width: 1 height: 18 draw_bg.color: Cborder }
                            btn_files := Button { text: "📁 Files" draw_bg.color: Cbar width: Fit height: 26 padding: Inset{left: 8.0 right: 8.0 top: 2.0 bottom: 2.0} draw_text.text_style: theme.font_regular{font_size: 11} }
                            btn_procs := Button { text: "⚙️ Processes" draw_bg.color: Cbar width: Fit height: 26 padding: Inset{left: 8.0 right: 8.0 top: 2.0 bottom: 2.0} draw_text.text_style: theme.font_regular{font_size: 11} }
                            btn_creds := Button { text: "🔑 Creds" draw_bg.color: Cbar width: Fit height: 26 padding: Inset{left: 8.0 right: 8.0 top: 2.0 bottom: 2.0} draw_text.text_style: theme.font_regular{font_size: 11} }
                            btn_event_log := Button { text: "📋 Event Log" draw_bg.color: Cbar width: Fit height: 26 padding: Inset{left: 8.0 right: 8.0 top: 2.0 bottom: 2.0} draw_text.text_style: theme.font_regular{font_size: 11} }
                            
                            View { width: Fill height: 1 }
                            main_btn_theme := Button { 
                                text: "🌗" 
                                draw_bg.color: Cbar 
                                width: 26 height: 26 
                                padding: Inset{left: 0.0 right: 0.0 top: 0.0 bottom: 0.0} 
                                draw_text.text_style: theme.font_regular{font_size: 14} 
                                draw_bg.border_radius: 13.0 
                            }
                        }

                        div_tool := View { width: Fill height: 1 draw_bg.color: Cborder }

                    // ── connection bar ─────────────────────────────────────
                    conn_bar := View{
                        show_bg: true
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
                        reconnect_group := View {
                            width: Fit height: Fit
                            flow: Right spacing: 12.0
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
                                draw_text.color: Cbg
                                draw_text.text_style: theme.font_bold{font_size: 12}
                            }
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
                    }
                    // hairline under connection bar
                    div_conn_bar := View{width: Fill height: 1 visible: false draw_bg.color: Cborder}

                    // ── main body: top (sessions+log) | bottom (tabs) ──────────
                    main_split := Splitter{
                        width: Fill height: Fill
                        axis: Vertical
                        align: FromA(350.0)

                        // Top Pane: Sessions visualizer (both Table & Graph)
                        a: View {
                            width: Fill height: Fill
                            padding: Inset{top: 8.0 bottom: 4.0 left: 8.0 right: 8.0}
                            left_panel := RoundedView{
                                width: Fill height: Fill
                                flow: Down spacing: 0
                                draw_bg.color: Cpanel
                                draw_bg.border_color: Cborder
                                draw_bg.border_radius: 8.0
                                draw_bg.border_size: 1.0
                                
                                sessions_header := View{
                                    width: Fill height: 32
                                    padding: Inset{left: 14.0 right: 14.0}
                                    flow: Right spacing: 8.0
                                    align: Align{y: 0.5}
                                    draw_bg.color: Cbar
                                    sessions_header_stripe := View{width: 3 height: 14 draw_bg.color: Caccent}
                                    sessions_header_title := Label{text: "SESSIONS" draw_text.color: Cprimary draw_text.text_style: theme.font_bold{font_size: 11}}
                                }
                                session_list_view := View {
                                    width: Fill height: Fill
                                    visible: true
                                    session_list := mod.widgets.SessionList{}
                                }
                                session_graph_view := View {
                                    width: Fill height: Fill
                                    visible: false
                                    session_graph := mod.widgets.SessionGraph{}
                                }
                                pane_files := View{
                                    width: Fill height: Fill
                                    visible: false
                                    flow: Down spacing: 0
                                    // File browser toolbar.
                                    View{
                                        width: Fill height: 34
                                        padding: Inset{left: 12.0 right: 12.0}
                                        flow: Right spacing: 8.0
                                        align: Align{y: 0.5}
                                        draw_bg.color: Cpanel
                                        path_input := TextInput{
                                            width: 300 height: 26
                                            label_align: Align{y: 0.5}
                                            padding: Inset{left: 8.0, right: 8.0, top: 4.0, bottom: 4.0}
                                            text: "."
                                            empty_text: "Remote path"
                                            draw_bg.color: Cinput
                                            draw_bg.border_color: Cinput_b
                                            draw_bg.border_color_focus: Caccent
                                            draw_bg.border_size: 1.0
                                            draw_bg.border_radius: 4.0
                                            draw_text.color: Cprimary
                                            draw_text.color_empty: Cmuted
                                            draw_text.text_style: theme.font_code{font_size: 12}
                                            draw_cursor.color: Caccent
                                        }
                                        ls_btn := Button{
                                            text: "List"
                                            width: 60 height: 26
                                            draw_bg.color: Caccent
                                            draw_bg.color_hover: Cacchov
                                            draw_bg.border_radius: 4.0
                                            draw_text.color: Cbg
                                            draw_text.text_style: theme.font_bold{font_size: 11}
                                        }
                                    }
                                    View{width: Fill height: 1 draw_bg.color: Cborder}
                                    mod.widgets.FileTree{}
                                }
                                pane_procs := View{
                                    width: Fill height: Fill
                                    visible: false
                                    flow: Down spacing: 0
                                    // Processes toolbar.
                                    View{
                                        width: Fill height: 34
                                        padding: Inset{left: 12.0 right: 12.0}
                                        flow: Right spacing: 0
                                        align: Align{y: 0.5}
                                        draw_bg.color: Cpanel
                                        ps_btn := Button{
                                            text: "Refresh"
                                            width: 76 height: 26
                                            draw_bg.color: Caccent
                                            draw_bg.color_hover: Cacchov
                                            draw_bg.border_radius: 4.0
                                            draw_text.color: Cbg
                                            draw_text.text_style: theme.font_bold{font_size: 11}
                                        }
                                    }
                                    View{width: Fill height: 1 draw_bg.color: Cborder}
                                    mod.widgets.ProcessTable{}
                                }
                                pane_creds := View{
                                    width: Fill height: Fill
                                    visible: false
                                    mod.widgets.CredTable{}
                                }
                                pane_event_log := View{
                                    width: Fill height: Fill
                                    visible: false
                                    flow: Down spacing: 0
                                    log_list := mod.widgets.LogList{}
                                }
                            }
                        }

                        // Bottom Pane: Interactive Tabs (Console, Files, Procs, etc.)
                        b: View {
                            width: Fill height: Fill
                            padding: Inset{top: 4.0 bottom: 8.0 left: 8.0 right: 8.0}
                            center_panel := RoundedView{
                                width: Fill height: Fill
                                flow: Down spacing: 0
                                draw_bg.color: Cpanel
                                draw_bg.border_color: Cborder
                                draw_bg.border_radius: 8.0
                                draw_bg.border_size: 1.0

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
                                }
                                // hairline under tab bar
                                div_tab_bar := View{width: Fill height: 1 draw_bg.color: Cborder}

                                // ── tab bodies (toggled via set_visible) ───────
                                // Console pane: scrollable output + command input bar.
                                pane_console := View{
                                    width: Fill height: Fill
                                    flow: Down spacing: 0

                                    // Output area — session-specific console output.
                                    console_output := View{
                                        width: Fill height: Fill
                                        flow: Down spacing: 0
                                        draw_bg.color: Cbg
                                        // No-session placeholder (shown via visible toggle).
                                        no_session_view := View{
                                            width: Fill height: Fill
                                            align: Center flow: Down spacing: 8.0
                                            center_text := Label{
                                                text: "No beacon selected"
                                                draw_text.color: Cmuted
                                                draw_text.text_style: theme.font_bold{font_size: 14}
                                            }
                                            center_sub := Label{
                                                text: "Select a session from the beacon list to open the interactive console"
                                                draw_text.color: Cmuted
                                                draw_text.text_style: theme.font_regular{font_size: 11}
                                            }
                                        }
                                        // Active session: output log.
                                        console_log_view := View{
                                            width: Fill height: Fill
                                            flow: Down spacing: 0
                                            visible: false
                                            // Beacon identity bar.
                                            beacon_bar := View{
                                                width: Fill height: 28
                                                padding: Inset{left: 12.0 right: 12.0}
                                                flow: Right spacing: 10.0
                                                align: Align{y: 0.5}
                                                draw_bg.color: Cbar
                                                View{width: 3 height: 12 draw_bg.color: Csuccess}
                                                beacon_info := Label{
                                                    text: "beacon · select a session"
                                                    draw_text.color: Csecond
                                                    draw_text.text_style: theme.font_code{font_size: 11}
                                                }
                                            }
                                            View{width: Fill height: 1 draw_bg.color: Cborder}
                                            // Virtualized output list.
                                            console_list := mod.widgets.ConsoleList{}
                                        }
                                    }
                                    // Command input bar.
                                    View{width: Fill height: 1 draw_bg.color: Cborder}
                                    cmd_bar := View{
                                        width: Fill height: 36
                                        padding: Inset{left: 12.0 right: 8.0}
                                        flow: Right spacing: 8.0
                                        align: Align{y: 0.5}
                                        draw_bg.color: Cpanel
                                        // Prompt glyph.
                                        Label{
                                            text: ">"
                                            draw_text.color: Caccent
                                            draw_text.text_style: theme.font_bold{font_size: 13}
                                        }
                                        cmd_input := TextInput{
                                            width: Fill height: 26
                                            label_align: Align{y: 0.5}
                                            padding: Inset{left: 8.0, right: 8.0, top: 4.0, bottom: 4.0}
                                            text: ""
                                            empty_text: "Enter command…"
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
                                            draw_bg.border_radius: 4.0
                                            draw_text.color: Cprimary
                                            draw_text.color_hover: Cprimary
                                            draw_text.color_focus: Cprimary
                                            draw_text.color_empty: Cmuted
                                            draw_text.text_style: theme.font_code{font_size: 12}
                                            draw_cursor.color: Caccent
                                        }
                                        send_btn := Button{
                                            text: "Send"
                                            width: 56 height: 26
                                            draw_bg.color: Caccent
                                            draw_bg.color_hover: Cacchov
                                            draw_bg.border_radius: 4.0
                                            draw_text.color: Cbg
                                            draw_text.text_style: theme.font_bold{font_size: 11}
                                        }
                                    }
                                }
                                }
                                pane_bof := View{
                                    width: Fill height: Fill
                                    visible: false
                                    flow: Down spacing: 0
                                    // BOF submit bar at top.
                                    bof_input_bar := View{
                                        width: Fill height: Fit
                                        flow: Down spacing: 0
                                        draw_bg.color: Cpanel
                                        View{
                                            width: Fill height: 36
                                            padding: Inset{left: 12.0 right: 12.0}
                                            flow: Right spacing: 8.0
                                            align: Align{y: 0.5}
                                            bof_name_input := TextInput{
                                                width: 200 height: 26
                                                label_align: Align{y: 0.5}
                                                padding: Inset{left: 8.0, right: 8.0, top: 4.0, bottom: 4.0}
                                                text: ""
                                                empty_text: "BOF object name"
                                                draw_bg.color: Cinput
                                                draw_bg.border_color: Cinput_b
                                                draw_bg.border_color_focus: Caccent
                                                draw_bg.border_size: 1.0
                                                draw_bg.border_radius: 4.0
                                                draw_text.color: Cprimary
                                                draw_text.color_empty: Cmuted
                                                draw_text.text_style: theme.font_code{font_size: 12}
                                                draw_cursor.color: Caccent
                                            }
                                            bof_args_input := TextInput{
                                                width: Fill height: 26
                                                label_align: Align{y: 0.5}
                                                padding: Inset{left: 8.0, right: 8.0, top: 4.0, bottom: 4.0}
                                                text: ""
                                                empty_text: "Arguments (space-separated)"
                                                draw_bg.color: Cinput
                                                draw_bg.border_color: Cinput_b
                                                draw_bg.border_color_focus: Caccent
                                                draw_bg.border_size: 1.0
                                                draw_bg.border_radius: 4.0
                                                draw_text.color: Cprimary
                                                draw_text.color_empty: Cmuted
                                                draw_text.text_style: theme.font_code{font_size: 12}
                                                draw_cursor.color: Caccent
                                            }
                                            bof_run_btn := Button{
                                                text: "Run BOF"
                                                width: 80 height: 26
                                                draw_bg.color: Caccent
                                                draw_bg.color_hover: Cacchov
                                                draw_bg.border_radius: 4.0
                                                draw_text.color: Cbg
                                                draw_text.text_style: theme.font_bold{font_size: 11}
                                            }
                                        }
                                        View{width: Fill height: 1 draw_bg.color: Cborder}
                                    }
                                    mod.widgets.BofPanel{}
                                }

                            }
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
}

impl Default for Tab {
    fn default() -> Self {
        Tab::Console
    }
}

/// A dialog form field that can carry an inline error. Used by
/// [`App::set_field_error`] to route validation/backend errors to the right
/// `*_error` label without scattering raw `ids!()` paths around.
#[derive(Clone, Copy)]
enum Field {
    Url,
    Alias,
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
        if !snap.console_lines.is_empty() {
            let mut console = CONSOLE.write().unwrap();
            for (sid, line) in snap.console_lines {
                console.entry(sid).or_default().push(line);
            }
        }
        self.set_status(cx, snap.connected);
        // Grow the window to full console size on the connect TRANSITION. The
        // login view uses a compact 420x580 window; the console needs 1280x800.
        // has_connected is sticky so this fires exactly once.
        if snap.connected && !self.has_connected {
            self.ui.window(cx, ids!(main_window)).resize(cx, dvec2(1280.0, 800.0));
        }
        if snap.connected {
            self.has_connected = true;
        }
        // If we have ever connected successfully, we remain in the console view.
        // If we haven't connected yet, keep showing the connect dialog.
        self.ui.view(cx, ids!(connect_view)).set_visible(cx, !self.has_connected);
        self.ui.view(cx, ids!(main_view)).set_visible(cx, self.has_connected);
        if !snap.connected && !self.has_connected {
            // Route the most recent backend error line to the field it most
            // likely came from, so the failure reads as "this field" instead of
            // a bottom-of-form blob. The bridge prefixes worker errors with
            // "! " (e.g. "! sessions: error sending request..."); reqwest
            // embeds the cause (connection refused / dns / status code) in the
            // message text, so substring matching is reliable here.
            let last_err = LOG_LINES.read().unwrap().last().cloned();
            if let Some(e) = last_err {
                let lower = e.to_lowercase();
                if lower.contains("connection refused")
                    || lower.contains("timed out")
                    || lower.contains("timeout")
                    || lower.contains("dns")
                    || lower.contains("unreachable")
                    || lower.contains("connect error")
                    || lower.contains("error connecting")
                {
                    self.set_field_error(cx, Field::Url, "Could not reach server at this address");
                    self.set_field_error(cx, Field::Alias, "");
                    self.ui.label(cx, ids!(connect_status)).set_text(cx, "");
                    self.ui.view(cx, ids!(connect_status)).set_visible(cx, false);
                } else if lower.contains("401")
                    || lower.contains("403")
                    || lower.contains("unauthorized")
                    || lower.contains("forbidden")
                    || lower.contains("invalid token")
                {
                    // No dedicated pass_error label — surface auth failures on
                    // the password field's column via the status line, since
                    // the helper text already occupies the slot right below it.
                    self.set_field_error(cx, Field::Url, "");
                    self.set_field_error(cx, Field::Alias, "");
                    self.ui
                        .label(cx, ids!(connect_status))
                        .set_text(cx, "Authentication failed — check your API token");
                    self.ui.view(cx, ids!(connect_status)).set_visible(cx, true);
                } else {
                    // Unattributable (e.g. 500, malformed response): keep the
                    // full text on the fallback status line so nothing is lost.
                    self.ui.label(cx, ids!(connect_status)).set_text(cx, &e);
                    self.ui.view(cx, ids!(connect_status)).set_visible(cx, !e.is_empty());
                }
            }
        }
        self.ui.redraw(cx);
    }

    fn set_status(&self, cx: &mut Cx, connected: bool) {
        // Two static dots (one green, one red); toggle visibility. Avoids the
        // unverified `apply_over`/`live!` rust-side color API — uses only the
        // documented `.set_visible()` from the `todo` example.
        self.ui.view(cx, ids!(conn_bar)).set_visible(cx, !connected);
        self.ui.view(cx, ids!(div_conn_bar)).set_visible(cx, !connected);
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

    /// Which dialog field an inline error belongs to. Used by
    /// [`set_field_error`](App::set_field_error) and
    /// [`validate_connect_form`](App::validate_connect_form) so the routing
    /// logic and the rendering both name fields symbolically.
    fn set_field_error(&self, cx: &mut Cx, field: Field, msg: &str) {
        let path = match field {
            Field::Url => ids!(url_error),
            Field::Alias => ids!(alias_error),
        };
        let has_msg = !msg.is_empty();
        self.ui.label(cx, path).set_text(cx, msg);
        self.ui.view(cx, path).set_visible(cx, has_msg);
    }

    /// Client-side gate run before sending `Cmd::Connect`. Returns true iff the
    /// form is valid; otherwise writes an inline message under the offending
    /// field and leaves the connect attempt unstarted. Backend errors (refused,
    /// auth) are handled separately in [`apply_snapshot`](App::apply_snapshot).
    ///
    /// Rules:
    /// * URL must look like `http(s)://host:port` — scheme, host, and a 2–5
    ///   digit port. Path/query are allowed but ignored. Intentionally a regex
    ///   sanity check, not an RFC 3986 parse: it catches fat-finger mistakes
    ///   without dragging in a URL crate or rejecting exotic-but-valid hosts.
    /// * Operator must be non-empty (it becomes the operator identity).
    /// * Password is optional (local dev server without NYX_TOKEN).
    fn validate_connect_form(&self, cx: &mut Cx) -> bool {
        let url = self.ui.text_input(cx, ids!(url_input)).text();
        let alias = self.ui.text_input(cx, ids!(alias_input)).text();

        let url_ok = {
            // Anchored regex via the `regex`-style manual scan would need a
            // dependency; a hand-rolled check is enough for a login gate.
            let u = url.trim();
            let scheme_ok =
                u.starts_with("http://") || u.starts_with("https://");
            let rest = u.split_once("://").map(|(_, r)| r).unwrap_or("");
            // host (non-empty, no slash/colon before the port) + :port(2-5)
            let host_port = rest.split('/').next().unwrap_or("");
            let (host, port) = host_port
                .rsplit_once(':')
                .map(|(h, p)| (h, Some(p)))
                .unwrap_or((host_port, None));
            let host_ok = !host.is_empty()
                && !host.contains(' ')
                && host.chars().any(|c| c != '.');
            let port_ok = port
                .map(|p| p.len() >= 2 && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
            scheme_ok && host_ok && port_ok
        };

        let alias_ok = !alias.trim().is_empty();

        // Always re-set both so a corrected field clears its old error.
        self.set_field_error(
            cx,
            Field::Url,
            if url_ok { "" } else { "Enter a valid http(s)://host:port URL" },
        );
        self.set_field_error(
            cx,
            Field::Alias,
            if alias_ok { "" } else { "Operator name is required" },
        );

        url_ok && alias_ok
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
        let csecond = p.second;
        let cmuted = p.muted;
        let caccent = p.accent;
        let cacchov = p.acchov;
        let crowhov = p.rowhov;
        let cinput = p.input;
        let cinput_b = p.input_b;
        let cbtn_grad2 = p.btn_grad2;
        let cwhite = vec4(1.0, 1.0, 1.0, 1.0);

        // 1. MainWindow clear_color
        let mut w = self.ui.window(cx, ids!(main_window));
        script_apply_eval!(cx, w, {
            pass +: { clear_color: #(cbg) }
        });

        // 1b. main_view background
        let mut mv = self.ui.view(cx, ids!(main_view));
        script_apply_eval!(cx, mv, {
            draw_bg +: { color: #(cbg) }
        });

        // 2. Dialog backdrop — just the window clear color now (no network bg).
        let mut cv = self.ui.view(cx, ids!(connect_view));
        script_apply_eval!(cx, cv, {
            draw_bg +: { color: #(celev) }
        });

        // 2b. Glass card (View) — per-theme tint / glow border.
        let mut cc = self.ui.view(cx, ids!(connect_card));
        script_apply_eval!(cx, cc, {
            draw_bg +: { color: #(celev) }
        });

        let mut lb = self.ui.view(cx, ids!(logo_box));
        script_apply_eval!(cx, lb, {
            draw_bg +: { color: #(caccent) }
        });
        let mut ll = self.ui.label(cx, ids!(logo_letter));
        script_apply_eval!(cx, ll, {
            draw_text +: { color: #(celev) }
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
                draw_bg +: {
                    color: #(cinput),
                    color_hover: #(cinput),
                    color_focus: #(cinput),
                    color_empty: #(cinput),
                    border_color: #(cinput_b),
                    border_color_hover: #(cinput_b),
                    border_color_focus: #(caccent),
                    border_color_empty: #(cinput_b),
                    border_color_2: #(cinput_b),
                    border_color_2_hover: #(cinput_b),
                    border_color_2_focus: #(caccent),
                    border_color_2_empty: #(cinput_b)
                }
                draw_text +: { color: #(cprimary), color_hover: #(cprimary), color_focus: #(cprimary), color_empty: #(csecond), color_empty_hover: #(csecond), color_empty_focus: #(csecond) }
                draw_cursor +: { color: #(caccent) }
            });
        }

        // 4. Buttons.
        let buttons = [
            (ids!(bar_connect_btn), caccent, cacchov, cwhite),
        ];
        for (path, bg, bg_hov, fg) in buttons {
            let mut btn = self.ui.button(cx, path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(bg), color_hover: #(bg_hov), color_down: #(bg) }
                draw_text +: { color: #(fg), color_hover: #(fg), color_down: #(fg) }
            });
        }

        // 4a. Theme Toggle controls
        let mut view = self.ui.view(cx, ids!(theme_toggle_dialog));
        script_apply_eval!(cx, view, {
            draw_bg +: { color: #(cinput), border_color: #(cinput_b) }
        });

        let mut dialog_btn = self.ui.button(cx, ids!(dialog_btn_theme));
        script_apply_eval!(cx, dialog_btn, {
            draw_bg +: { color: #(cinput), color_hover: #(crowhov), color_down: #(crowhov) }
            draw_text +: { color: #(cprimary), color_hover: #(cprimary), color_down: #(cprimary) }
        });

        // 4b. Connect button gradient.
        let mut cbtn = self.ui.button(cx, ids!(dialog_connect_btn));
        script_apply_eval!(cx, cbtn, {
            draw_bg +: {
                color: #(caccent),
                color_2: #(cbtn_grad2),
                color_hover: #(cacchov),
                color_2_hover: #(cbtn_grad2),
                color_down: #(caccent),
                color_2_down: #(cbtn_grad2),
                gradient_fill_horizontal: 1.0
            }
            draw_text +: {
                color: #(cwhite),
                color_hover: #(cwhite),
                color_down: #(cwhite)
            }
        });

        // 5. Dialog text: error status, wordmark/tagline/title, field labels.
        let mut cs_lbl = self.ui.label(cx, ids!(connect_status));
        script_apply_eval!(cx, cs_lbl, {
            draw_text +: { color: #(p.danger) }
        });
        let field_errors = [
            ids!(url_error),
            ids!(alias_error),
        ];
        for path in field_errors {
            let mut lbl = self.ui.label(cx, path);
            script_apply_eval!(cx, lbl, {
                draw_text +: { color: #(p.danger) }
            });
        }
        let dialog_labels = [
            (ids!(nyx_logo), cprimary),
            (ids!(connect_tagline), csecond),
            (ids!(url_label), csecond),
            (ids!(alias_label), csecond),
            (ids!(pass_label), csecond),
            (ids!(pass_helper), csecond),
            (ids!(connect_footer), csecond),
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
            draw_bg +: { color: #(cpanel), border_color: #(cborder) }
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
            draw_bg +: { color: #(cpanel), border_color: #(cborder) }
        });
        let mut tb = self.ui.view(cx, ids!(tab_bar));
        script_apply_eval!(cx, tb, {
            draw_bg +: { color: #(cbar) }
        });

        // Tab buttons + their active underlines.
        let tabs = [
            (ids!(tab_console), ids!(line_console)),
            (ids!(tab_bof), ids!(line_bof)),
        ];
        for (btn_path, line_path) in tabs {
            let mut btn = self.ui.button(cx, btn_path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(cbar), color_hover: #(crowhov), color_down: #(crowhov) }
                draw_text +: { color: #(cprimary), color_hover: #(caccent), color_down: #(caccent) }
            });
            let mut line = self.ui.view(cx, line_path);
            script_apply_eval!(cx, line, {
                draw_bg +: { color: #(caccent) }
            });
        }

        // Center console: style the "no beacon" placeholder + beacon info bar.
        let mut ctxt = self.ui.label(cx, ids!(center_text));
        script_apply_eval!(cx, ctxt, {
            draw_text +: { color: #(cmuted) }
        });
        let mut csub = self.ui.label(cx, ids!(center_sub));
        script_apply_eval!(cx, csub, {
            draw_text +: { color: #(cmuted) }
        });
        let mut bi = self.ui.label(cx, ids!(beacon_info));
        script_apply_eval!(cx, bi, {
            draw_text +: { color: #(csecond) }
        });

        // Command bar background.
        let mut cb = self.ui.view(cx, ids!(cmd_bar));
        script_apply_eval!(cx, cb, {
            draw_bg +: { color: #(cpanel) }
        });
        // cmd_input styling.
        let mut ci = self.ui.text_input(cx, ids!(cmd_input));
        script_apply_eval!(cx, ci, {
            draw_bg +: {
                color: #(cinput), color_hover: #(cinput), color_focus: #(cinput), color_empty: #(cinput),
                border_color: #(cinput_b), border_color_hover: #(cinput_b), border_color_focus: #(caccent),
                border_color_empty: #(cinput_b), border_color_2: #(cinput_b), border_color_2_hover: #(cinput_b),
                border_color_2_focus: #(caccent), border_color_2_empty: #(cinput_b)
            }
            draw_text +: { color: #(cprimary), color_hover: #(cprimary), color_focus: #(cprimary), color_empty: #(cmuted) }
            draw_cursor +: { color: #(caccent) }
        });
        // Send button.
        let mut sb = self.ui.button(cx, ids!(send_btn));
        script_apply_eval!(cx, sb, {
            draw_bg +: { color: #(caccent), color_hover: #(cacchov), color_down: #(cacchov) }
            draw_text +: { color: #(cbg), color_hover: #(cbg), color_down: #(cbg) }
        });

        // MenuBar styling
        let mut mb = self.ui.view(cx, ids!(menu_bar));
        script_apply_eval!(cx, mb, {
            draw_bg +: { color: #(cbar) }
        });
        let menu_buttons = [
            ids!(menu_nyx),
            ids!(menu_view),
            ids!(menu_attacks),
            ids!(menu_reporting),
            ids!(menu_help),
        ];
        for path in menu_buttons {
            let mut btn = self.ui.button(cx, path);
            let text_color = if is_dark { vec4(1.0, 1.0, 1.0, 1.0) } else { cprimary };
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #x00000000, color_hover: #(crowhov), color_down: #(crowhov), border_size: 0.0 }
                draw_text +: { color: #(text_color), color_hover: #(text_color), color_down: #(text_color) }
            });
        }

        // ToolBar styling
        let mut tb_view = self.ui.view(cx, ids!(tool_bar));
        script_apply_eval!(cx, tb_view, {
            draw_bg +: { color: #(cpanel) }
        });
        let toolbar_buttons = [
            ids!(btn_table),
            ids!(btn_graph),
            ids!(btn_files),
            ids!(btn_procs),
            ids!(btn_creds),
            ids!(btn_event_log),
            ids!(main_btn_theme),
        ];
        for path in toolbar_buttons {
            let mut btn = self.ui.button(cx, path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(cbar), color_hover: #(crowhov), color_down: #(crowhov) }
                draw_text +: { color: #(cprimary), color_hover: #(cprimary), color_down: #(cprimary) }
            });
        }

        // 9. Hairlines / dividers.
        let dividers = [
            ids!(div_conn_bar),
            ids!(div_brand),
            ids!(div_tab_bar),
            ids!(div_menu),
            ids!(div_tool),
            ids!(div_1),
            ids!(div_2),
        ];
        for path in dividers {
            let mut div = self.ui.view(cx, path);
            script_apply_eval!(cx, div, {
                draw_bg +: { color: #(cborder) }
            });
        }
        
        // 10. Toolbar buttons (ls, ps, bof_run) and inputs.
        for btn_path in [ids!(bof_run_btn), ids!(ls_btn), ids!(ps_btn)] {
            let mut btn = self.ui.button(cx, btn_path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(caccent), color_hover: #(cacchov), color_down: #(cacchov) }
                draw_text +: { color: #(cwhite), color_hover: #(cwhite), color_down: #(cwhite) }
            });
        }
        for inp_path in [ids!(bof_name_input), ids!(bof_args_input), ids!(path_input)] {
            let mut inp = self.ui.text_input(cx, inp_path);
            script_apply_eval!(cx, inp, {
                draw_bg +: {
                    color: #(cinput), color_hover: #(cinput), color_focus: #(cinput), color_empty: #(cinput),
                    border_color: #(cinput_b), border_color_focus: #(caccent)
                }
                draw_text +: { color: #(cprimary), color_empty: #(cmuted) }
                draw_cursor +: { color: #(caccent) }
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
        ];
        for (t, id) in panes {
            self.ui.view(cx, id).set_visible(cx, t == tab);
        }
        // Toggle the visibility of active tab gold underlines.
        let lines = [
            (Tab::Console, ids!(line_console)),
            (Tab::Bof, ids!(line_bof)),
        ];
        for (t, id) in lines {
            self.ui.view(cx, id).set_visible(cx, t == tab);
        }
        self.ui.redraw(cx);
    }
}

impl MatchEvent for App {
    fn handle_startup(&mut self, cx: &mut Cx) {
        self.is_dark = std::env::var("NYX_START_DARK").is_ok();
        IS_DARK.store(self.is_dark, std::sync::atomic::Ordering::Relaxed);
        let label_text = if self.is_dark { "THEME: DARK" } else { "THEME: LIGHT" };
        self.ui.button(cx, ids!(dialog_btn_theme)).set_text(cx, label_text);
        self.ui.button(cx, ids!(main_btn_theme)).set_text(cx, label_text);
        self.set_status(cx, false);
        self.ui.window(cx, ids!(main_window)).resize(cx, dvec2(360.0, 480.0));
        self.apply_theme(cx);
        self.ui.redraw(cx);

        if std::env::var("NYX_AUTO_CONNECT").is_ok() {
            self.ensure_bridge();
            if let Some(b) = &self.bridge {
                let _ = b.from_ui.send(Cmd::Connect {
                    server: "http://127.0.0.1:8443".to_string(),
                    password: None,
                });
            }
        }
    }

    fn handle_actions(&mut self, cx: &mut Cx, actions: &Actions) {
        // Theme toggle button click
        let clicked_theme = self.ui.button(cx, ids!(dialog_btn_theme)).clicked(actions)
            || self.ui.button(cx, ids!(main_btn_theme)).clicked(actions);

        if clicked_theme {
            self.is_dark = !self.is_dark;
            IS_DARK.store(self.is_dark, std::sync::atomic::Ordering::Relaxed);
            
            let label_text = if self.is_dark { "THEME: DARK" } else { "THEME: LIGHT" };
            self.ui.button(cx, ids!(dialog_btn_theme)).set_text(cx, label_text);
            self.ui.button(cx, ids!(main_btn_theme)).set_text(cx, label_text);
            
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
        // Toolbar buttons click handlers (Top Pane visibility)
        let top_panes = [
            ids!(session_list_view),
            ids!(session_graph_view),
            ids!(pane_files),
            ids!(pane_procs),
            ids!(pane_creds),
            ids!(pane_event_log),
        ];

        let mut clicked_toolbar = None;
        if self.ui.button(cx, ids!(btn_table)).clicked(actions) { clicked_toolbar = Some(ids!(session_list_view)); }
        else if self.ui.button(cx, ids!(btn_graph)).clicked(actions) { clicked_toolbar = Some(ids!(session_graph_view)); }
        else if self.ui.button(cx, ids!(btn_files)).clicked(actions) { clicked_toolbar = Some(ids!(pane_files)); }
        else if self.ui.button(cx, ids!(btn_procs)).clicked(actions) { clicked_toolbar = Some(ids!(pane_procs)); }
        else if self.ui.button(cx, ids!(btn_creds)).clicked(actions) { clicked_toolbar = Some(ids!(pane_creds)); }
        else if self.ui.button(cx, ids!(btn_event_log)).clicked(actions) { clicked_toolbar = Some(ids!(pane_event_log)); }

        if let Some(target) = clicked_toolbar {
            for &id in &top_panes {
                self.ui.view(cx, id).set_visible(cx, id == target);
            }
            self.ui.redraw(cx);
        }

        // Top bar buttons dummy actions (so they do something)
        let top_buttons = [ids!(menu_nyx), ids!(menu_view), ids!(menu_attacks), ids!(menu_reporting), ids!(menu_help)];
        for id in top_buttons {
            if self.ui.button(cx, id).clicked(actions) {
                // For now just redraw to register the click visually
                self.ui.redraw(cx);
            }
        }

        // ── Connect dialog (the dedicated connect window) ────────────────
        // Connect button OR Enter in any connect-dialog field.
        let dlg_connect = self.ui.button(cx, ids!(dialog_connect_btn)).clicked(actions);
        let dlg_enter = self.ui.text_input(cx, ids!(url_input)).returned(actions).is_some()
            || self.ui.text_input(cx, ids!(alias_input)).returned(actions).is_some()
            || self.ui.text_input(cx, ids!(pass_input)).returned(actions).is_some();

        let bar_connect = self.ui.button(cx, ids!(bar_connect_btn)).clicked(actions);

        if dlg_connect || dlg_enter || bar_connect {
            // Front-end validation gate (dialog path only). The connection-bar
            // field is a quick reconnect control, so it skips this and trusts
            // whatever the operator types. On failure we abort BEFORE spawning
            // the bridge attempt and let the inline errors speak.
            if !bar_connect && !self.validate_connect_form(cx) {
                self.ui.redraw(cx);
            } else {
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
                        // Clear any stale inline errors — a fresh attempt is
                        // in flight; the next verdict comes from the backend.
                        self.set_field_error(cx, Field::Url, "");
                        self.set_field_error(cx, Field::Alias, "");
                        self.ui.label(cx, ids!(connect_status)).set_text(cx, "Connecting…");
                        self.ui.view(cx, ids!(connect_status)).set_visible(cx, true);
                    }
                }
            }
        }

        // Send command via Send button OR Enter in cmd_input.
        let send_clicked = self.ui.button(cx, ids!(send_btn)).clicked(actions);
        let cmd_entered = self.ui.text_input(cx, ids!(cmd_input)).returned(actions);
        if send_clicked || cmd_entered.is_some() {
            let raw = if let Some((v, _mods)) = cmd_entered {
                v
            } else {
                self.ui.text_input(cx, ids!(cmd_input)).text()
            };
            let cmd = raw.trim().to_string();
            if !cmd.is_empty() {
                self.ui.text_input(cx, ids!(cmd_input)).set_text(cx, "");
                let sel = SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
                if sel != usize::MAX {
                    let session_id = SESSIONS.read().unwrap().get(sel).map(|s| s.id.clone());
                    if let Some(sid) = session_id {
                        CONSOLE.write().unwrap().entry(sid.clone()).or_default().push(format!("$ {}", cmd));
                        self.ensure_bridge();
                        if let Some(b) = &self.bridge {
                            let parts: Vec<&str> = cmd.split_whitespace().collect();
                            let bridge_cmd = match parts.first().copied() {
                                Some("ping") => Cmd::Ping { session: sid.clone() },
                                Some("sleep") => {
                                    let secs = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(60);
                                    let jitter = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                                    Cmd::Sleep { session: sid.clone(), seconds: secs, jitter_pct: jitter }
                                }
                                Some("exit") => Cmd::Exit { session: sid.clone() },
                                Some("upload") => {
                                    let name = parts.get(1).copied().unwrap_or("").to_string();
                                    // Local file reading should ideally be async, but for now we read it here
                                    // Alternatively, we just send empty data if file not found, which will fail gracefully
                                    let data_hex = if let Ok(data) = std::fs::read(&name) { hex::encode(data) } else { String::new() };
                                    Cmd::Upload { session: sid.clone(), name, data_hex }
                                }
                                Some("download") => Cmd::Download { session: sid.clone(), path: parts.get(1).copied().unwrap_or("").to_string() },
                                Some("cd") | Some("mkdir") | Some("rm") => {
                                    Cmd::FileOp { session: sid.clone(), op: parts[0].to_string(), path: parts.get(1).copied().unwrap_or("").to_string(), dest: None }
                                }
                                Some("mv") | Some("cp") => {
                                    Cmd::FileOp { session: sid.clone(), op: parts[0].to_string(), path: parts.get(1).copied().unwrap_or("").to_string(), dest: parts.get(2).map(|s| s.to_string()) }
                                }
                                Some("ls") => Cmd::Ls { session: sid.clone(), args: cmd.clone() },
                                Some("ps") => Cmd::Ps { session: sid.clone(), args: cmd.clone() },
                                Some("screenshot") => Cmd::Screenshot { session: sid.clone(), monitor: parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0) },
                                Some("screenwatch") => Cmd::Screenwatch { session: sid.clone(), interval_secs: parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(5) },
                                Some("clipboard") => Cmd::Clipboard { session: sid.clone() },
                                Some("env") => Cmd::Env { session: sid.clone(), name: parts.get(1).copied().unwrap_or("").to_string() },
                                Some("keylog") => {
                                    let action_str = parts.get(1).copied().unwrap_or("start");
                                    let action = match action_str { "start" => 0, "stop" => 1, "dump" => 2, _ => 0 };
                                    Cmd::Keylog { session: sid.clone(), action }
                                }
                                Some("hashdump") => {
                                    let method_str = parts.get(1).copied().unwrap_or("lsass");
                                    let method = match method_str { "lsass" => 0, "shadow" => 1, _ => 0 };
                                    Cmd::Hashdump { session: sid.clone(), method }
                                }
                                Some("driveinfo") => Cmd::Driveinfo { session: sid.clone() },
                                Some("portscan") => Cmd::Portscan { session: sid.clone(), host: parts.get(1).copied().unwrap_or("").to_string(), ports: parts.get(2).copied().unwrap_or("").to_string() },
                                Some("net") => Cmd::Net { session: sid.clone(), query: parts.get(1).copied().unwrap_or("").to_string() },
                                Some("connect") => Cmd::ConnectChan { session: sid.clone(), host: parts.get(1).copied().unwrap_or("").to_string(), port: parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0) },
                                Some("socks") => {
                                    let chan = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                                    let op_str = parts.get(2).copied().unwrap_or("start");
                                    let op = match op_str { "start" => 0, "stop" => 1, _ => 0 };
                                    let addr = parts.get(3).copied().unwrap_or("").to_string();
                                    let port = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                                    Cmd::Socks { session: sid.clone(), chan, op, addr, port }
                                }
                                _ => Cmd::Shell { session: sid.clone(), args: cmd.clone() },
                            };
                            let _ = b.from_ui.send(bridge_cmd);
                        }
                    }
                } else {
                    LOG_LINES.write().unwrap().push("! No beacon selected — select a session first".to_string());
                }
                self.ui.redraw(cx);
            }
        }

        // BOF run button.
        if self.ui.button(cx, ids!(bof_run_btn)).clicked(actions) {
            let sel = SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
            if sel != usize::MAX {
                let session_id = SESSIONS.read().unwrap().get(sel).map(|s| s.id.clone());
                if let Some(sid) = session_id {
                    let name = self.ui.text_input(cx, ids!(bof_name_input)).text();
                    let args = self.ui.text_input(cx, ids!(bof_args_input)).text();
                    if !name.trim().is_empty() {
                        self.ensure_bridge();
                        if let Some(b) = &self.bridge {
                            let _ = b.from_ui.send(Cmd::Bof {
                                session: sid,
                                name: name.trim().to_string(),
                                args: args.trim().to_string(),
                                data_hex: String::new(),
                            });
                        }
                    } else {
                        LOG_LINES.write().unwrap().push("! BOF name is required".to_string());
                    }
                }
            } else {
                LOG_LINES.write().unwrap().push("! No beacon selected".to_string());
            }
            self.ui.redraw(cx);
        }

        // Files list (ls) button.
        if self.ui.button(cx, ids!(ls_btn)).clicked(actions) {
            let sel = SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
            if sel != usize::MAX {
                let session_id = SESSIONS.read().unwrap().get(sel).map(|s| s.id.clone());
                if let Some(sid) = session_id {
                    let path = self.ui.text_input(cx, ids!(path_input)).text();
                    self.ensure_bridge();
                    if let Some(b) = &self.bridge {
                        let _ = b.from_ui.send(Cmd::Ls {
                            session: sid,
                            args: format!("ls {}", path.trim()),
                        });
                    }
                }
            } else {
                LOG_LINES.write().unwrap().push("! No beacon selected".to_string());
            }
            self.ui.redraw(cx);
        }

        // Process table (ps) refresh button.
        if self.ui.button(cx, ids!(ps_btn)).clicked(actions) {
            let sel = SELECTED_SESSION.load(std::sync::atomic::Ordering::Relaxed);
            if sel != usize::MAX {
                let session_id = SESSIONS.read().unwrap().get(sel).map(|s| s.id.clone());
                if let Some(sid) = session_id {
                    self.ensure_bridge();
                    if let Some(b) = &self.bridge {
                        let _ = b.from_ui.send(Cmd::Ps {
                            session: sid,
                            args: "ps".to_string(),
                        });
                    }
                }
            } else {
                LOG_LINES.write().unwrap().push("! No beacon selected".to_string());
            }
            self.ui.redraw(cx);
        }

        // Disconnect button removed.


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
                let has_session = s.is_some();
                // Update the beacon identity bar in the console log view.
                if let Some(s) = s {
                    let info = format!("{} @ {}  ·  {}", s.hostname, s.username, &s.id[..8.min(s.id.len())]);
                    self.ui.label(cx, ids!(beacon_info)).set_text(cx, &info);
                }
                // Show/hide the placeholder vs. the active console log.
                self.ui
                    .view(cx, ids!(no_session_view))
                    .set_visible(cx, !has_session);
                self.ui
                    .view(cx, ids!(console_log_view))
                    .set_visible(cx, has_session);
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

// ── LogList widget (virtualized, reads LOG_LINES global) ────────────────────

#[derive(Script, ScriptHook, Widget)]
struct LogList {
    #[deref]
    view: View,
}

impl Widget for LogList {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        let lines_guard = LOG_LINES.read().unwrap_or_else(|e| e.into_inner());
        while let Some(step) = self.view.draw_walk(cx, scope, walk).step() {
            if let Some(mut list) = step.as_portal_list().borrow_mut() {
                list.set_item_range(cx, 0, lines_guard.len());
                while let Some(item_id) = list.next_visible_item(cx) {
                    let Some(line) = lines_guard.get(item_id) else { continue };
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
