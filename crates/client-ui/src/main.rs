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
    let Cbg       = #x16161E  // app background — deepest surface
    let Cinput    = #x2D2D3D  // input fill = elev (blend with card, no patch)
    let Cinput_b  = #x4A4A60  // visible input border (carries the boundary)
    let Cbar      = #x1B1B26  // recessed secondary bars / tab bar
    let Cpanel    = #x1B1B26  // side panels + event-log shell
    let Crow      = #x1B1B26  // table/data-row base
    let Crowhov   = #x353548  // row hover
    let Crowsel   = #x3A2A3E  // row selected (magenta-tinted)
    let Celev     = #x2D2D3D  // brightest surface — column headers / dialog card
    let Cborder   = #x3D3D50  // hairline dividers
    let Cprimary  = #xD4D4D4  // primary text
    let Csecond   = #xABABB2  // secondary text
    let Cmuted    = #x7F7F86  // muted text / column labels
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
            grad_top: instance(#x1A1A2E)
            grad_bot: instance(#x0F0F1A)
            node_color: instance(#x8B9DC3)
            line_color: instance(#x5A6BA0)

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
        width: 400 height: Fit
        flow: Down
        draw_bg +: {
            tint_color: instance(#x2D2D3D)
            tint_alpha: uniform(0.55)
            surface_alpha: uniform(0.82)
            border_color: instance(#xC586C0)
            border_alpha: instance(0.5)
            border_width: instance(1.0)
            corner_radius: instance(12.0)
            blur_level: uniform(4.0)
            shadow_color: instance(#x000000B3)
            shadow_radius: uniform(24.0)
            shadow_offset: uniform(vec2(0.0, 8.0))
            fallback_color: instance(#x2D2D3D)
        }
    }

    // ── theme switch (procedural sun/moon toggle) ───────────────────────────
    // Pure-DSL shader View: a pill track + sliding knob + sun (light) / moon
    // crescent (dark) drawn procedurally — IBMPlexSans has no ☀/☾ glyphs, so
    // we draw them in the shader instead. `is_dark` instance (1.0/0.0) drives
    // knob position + which glyph shows; apply_theme sets it. A transparent
    // overlay Button (reusing the dialog_theme_btn id) captures the click so
    // the existing handle_actions toggle path needs NO change.
    let ThemeSwitch = View{
        width: 76 height: 28
        flow: Overlay
        show_bg: true
        draw_bg +: {
            is_dark: instance(1.0)
            track_dark: instance(#x2A2A3E)
            track_light: instance(#xE8E0F0)
            knob_color: instance(#xF5F5F8)

            pixel: fn() {
                let sdf = Sdf2d.viewport(self.pos * self.rect_size)
                let w = self.rect_size.x
                let h = self.rect_size.y
                let r = h * 0.5

                // Pill track — color blends with state (mix = free fn, GLSL builtin).
                sdf.box(0.0, 0.0, w, h, r)
                sdf.fill(vec4(mix(self.track_light.rgb, self.track_dark.rgb, self.is_dark), 1.0))

                // Knob slides: is_dark=0 (light) → left, is_dark=1 (dark) → right.
                let knob_x = mix(r, w - r, self.is_dark)
                let kr = r * 0.72
                sdf.circle(knob_x, h * 0.5, kr)
                sdf.fill(self.knob_color)

                // Glyph INSIDE the knob: a sun disc when light (is_dark≈0),
                // a moon crescent when dark (is_dark≈1). Drawn at the knob's
                // own center so it always rides with the knob.
                if self.is_dark < 0.5 {
                    // Sun: warm disc, slightly smaller than the knob.
                    sdf.circle(knob_x, h * 0.5, kr * 0.6)
                    sdf.fill_keep(vec4(1.0, 0.78, 0.42, 1.0))
                } else {
                    // Moon: full disc then subtract an offset disc → crescent.
                    sdf.circle(knob_x, h * 0.5, kr * 0.62)
                    sdf.fill_keep(vec4(0.72, 0.77, 0.91, 1.0))
                    sdf.circle(knob_x + kr * 0.3, h * 0.5 - kr * 0.16, kr * 0.56)
                    sdf.subtract()
                }

                return sdf.result
            }
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
                window.inner_size: vec2(1024, 700)
                pass.clear_color: Cbg
                body +: {
                    width: Fill height: Fill
                    // flow: Overlay stacks the connect dialog on top of the
                    // main console. connect_view starts visible, main_view
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
                    connect_view := View{
                        width: Fill height: Fill
                        flow: Overlay
                        // Animated network background fills the whole view; the
                        // glass card overlays on top of it (Overlay z-order =
                        // source order, so later children sit above earlier).
                        network_bg := NetworkBg{width: Fill height: Fill}
                        // Centering wrapper for the card.
                        View{
                            width: Fill height: Fill
                            align: Center
                            draw_bg.color: #x00000000
                        // The dialog card — GlassCard (GaussRoundedView real blur).
                        connect_card := GlassCard{

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
                                        width: 32 height: 32
                                        draw_bg.color: Caccent
                                        draw_bg.border_radius: 7.0
                                        padding: Inset{top: 6.0}
                                        align: Align{x: 0.5 y: 0.5}
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
                                    draw_text.color: Csecond
                                    draw_text.text_style: theme.font_regular{font_size: 12}
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
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 20.0 bottom: 26.0 left: 30.0 right: 30.0}
                                flow: Down spacing: 16.0

                                // Server URL — host + port merged into one field
                                // (simpler than the old two-column HOST/PORT row).
                                View{
                                    width: Fill height: Fit flow: Down spacing: 3.0
                                    url_label := Label{text: "Server URL" draw_text.color: Csecond draw_text.text_style: theme.font_regular{font_size: 11}}
                                    url_input := TextInput{
                                        width: Fill height: 30
                                        label_align: Align{y: 0.5}
                                        // NOTE: Makepad's text layout ignores
                                        // Align.y for single-line text (only
                                        // align.x is used — see draw_text.rs
                                        // layout() → LayoutOptions.align). So
                                        // vertical centering is done by hand:
                                        // a top inset nudges the baseline down
                                        // into the visual middle of the 30pt
                                        // box. 7pt ≈ (30 − ~16pt line) / 2.
                                        padding: Inset{top: 7.0 left: 12.0 right: 12.0}
                                        text: "http://127.0.0.1:8443"
                                        empty_text: "http://host:port"
                                        draw_bg.color: Cinput
                                        draw_bg.color_hover: Cinput
                                        draw_bg.color_focus: Cinput
                                        draw_bg.border_color: Cinput_b
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
                                    // Inline error for the URL field. Empty by
                                    // default; validate_connect_form() + the
                                    // connection-refused route in apply_snapshot()
                                    // set its text. Lives INSIDE this field's
                                    // column, so it always reads as "this field".
                                    url_error := Label{
                                        text: ""
                                        draw_text.color: Cdanger
                                        draw_text.text_style: theme.font_code{font_size: 10}
                                    }
                                }
                                View{
                                    width: Fill height: Fit flow: Down spacing: 3.0
                                    alias_label := Label{text: "Operator" draw_text.color: Csecond draw_text.text_style: theme.font_regular{font_size: 11}}
                                    alias_input := TextInput{
                                        width: Fill height: 30
                                        label_align: Align{y: 0.5}
                                        // NOTE: Makepad's text layout ignores
                                        // Align.y for single-line text (only
                                        // align.x is used — see draw_text.rs
                                        // layout() → LayoutOptions.align). So
                                        // vertical centering is done by hand:
                                        // a top inset nudges the baseline down
                                        // into the visual middle of the 30pt
                                        // box. 7pt ≈ (30 − ~16pt line) / 2.
                                        padding: Inset{top: 7.0 left: 12.0 right: 12.0}
                                        text: "operator"
                                        draw_bg.color: Cinput
                                        draw_bg.color_hover: Cinput
                                        draw_bg.color_focus: Cinput
                                        draw_bg.border_color: Cinput_b
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
                                    alias_error := Label{
                                        text: ""
                                        draw_text.color: Cdanger
                                        draw_text.text_style: theme.font_code{font_size: 10}
                                    }
                                }
                                // Password = API bearer token. Flows into
                                // Cmd::Connect::password; the worker attaches it
                                // as `Authorization: Bearer`. Empty = no token
                                // (local dev server without NYX_TOKEN).
                                View{
                                    width: Fill height: Fit flow: Down spacing: 3.0
                                    pass_label := Label{text: "Password (API Token)" draw_text.color: Csecond draw_text.text_style: theme.font_regular{font_size: 11}}
                                    pass_input := TextInput{
                                        is_password: true
                                        width: Fill height: 30
                                        label_align: Align{y: 0.5}
                                        // NOTE: Makepad's text layout ignores
                                        // Align.y for single-line text (only
                                        // align.x is used — see draw_text.rs
                                        // layout() → LayoutOptions.align). So
                                        // vertical centering is done by hand:
                                        // a top inset nudges the baseline down
                                        // into the visual middle of the 30pt
                                        // box. 7pt ≈ (30 − ~16pt line) / 2.
                                        padding: Inset{top: 7.0 left: 12.0 right: 12.0}
                                        text: ""
                                        empty_text: "Enter Team Server Token"
                                        draw_bg.color: Cinput
                                        draw_bg.color_hover: Cinput
                                        draw_bg.color_focus: Cinput
                                        draw_bg.border_color: Cinput_b
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
                                    // Static helper (not an error): the "(leave
                                    // empty if none)" hint moved OUT of the
                                    // placeholder into a persistent micro-caption,
                                    // so the field's intent is obvious even after
                                    // the user starts typing.
                                    pass_helper := Label{
                                        text: "Leave empty if none"
                                        draw_text.color: Cmuted
                                        draw_text.text_style: theme.font_regular{font_size: 10}
                                    }
                                }
                                // Fallback status line — only used for errors we
                                // can't attribute to a specific field (e.g. a
                                // generic 500). Field-specific errors go to
                                // url_error / alias_error above. Kept for safety
                                // but no longer the primary error surface.
                                connect_status := Label{
                                    text: ""
                                    draw_text.color: Cdanger
                                    draw_text.text_style: theme.font_code{font_size: 11}
                                }
                                // Theme switch centered, then full-width Connect.
                                // The switch reuses the dialog_theme_btn id on
                                // its transparent overlay Button so the existing
                                // handle_actions toggle path is unchanged.
                                View{
                                    width: Fill height: Fit
                                    flow: Down spacing: 12.0
                                    View{
                                        width: Fill height: Fit
                                        align: Align{x: 0.5}
                                        theme_switch := ThemeSwitch{
                                            // Transparent hit-area button fills the pill.
                                            dialog_theme_btn := Button{
                                                width: Fill height: Fill
                                                text: ""
                                                draw_bg.color: #x00000000
                                                draw_bg.color_hover: #x00000000
                                                draw_text.color: #x00000000
                                            }
                                        }
                                    }
                                    dialog_connect_btn := Button{
                                        text: "Connect"
                                        width: Fill height: 38
                                        draw_bg.color: Caccent
                                        draw_bg.color_2: #x9B6BB5
                                        draw_bg.gradient_fill_horizontal: 1.0
                                        draw_bg.color_hover: Cacchov
                                        draw_bg.border_radius: 8.0
                                        draw_text.color: Cbg
                                        draw_text.text_style: theme.font_bold{font_size: 13}
                                    }
                                }
                                connect_footer := Label{
                                    text: "Authorized use only · all activity is logged"
                                    draw_text.color: Csecond
                                    draw_text.text_style: theme.font_regular{font_size: 11}
                                }
                            }
                        }
                        // (closes the centering wrapper View around connect_card)
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
                            label_align: Align{y: 0.5}
                            padding: Inset{top: 7.0 left: 10.0 right: 10.0}
                            text: "http://127.0.0.1:8443"
                            empty_text: "team server URL"
                            draw_bg.color: Cinput
                            draw_bg.color_hover: Cinput
                            draw_bg.color_focus: Cinput
                            draw_bg.border_color: Cinput_b
                            draw_bg.border_color_focus: Caccent
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
        self.set_status(cx, snap.connected);
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
                } else {
                    // Unattributable (e.g. 500, malformed response): keep the
                    // full text on the fallback status line so nothing is lost.
                    self.ui.label(cx, ids!(connect_status)).set_text(cx, &e);
                }
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

    /// Which dialog field an inline error belongs to. Used by
    /// [`set_field_error`](App::set_field_error) and
    /// [`validate_connect_form`](App::validate_connect_form) so the routing
    /// logic and the rendering both name fields symbolically.
    fn set_field_error(&self, cx: &mut Cx, field: Field, msg: &str) {
        let path = match field {
            Field::Url => ids!(url_error),
            Field::Alias => ids!(alias_error),
        };
        self.ui.label(cx, path).set_text(cx, msg);
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
        let cgrad_top = p.grad_top;
        let cgrad_bot = p.grad_bot;
        let cnode = p.node;
        let cline = p.line;
        let cglow = p.glow;
        let cbtn_grad2 = p.btn_grad2;

        // 1. MainWindow clear_color
        let mut w = self.ui.window(cx, ids!(main_window));
        script_apply_eval!(cx, w, {
            pass +: { clear_color: #(cbg) }
        });

        // 2. Dialog surfaces: backdrop (now transparent Overlay so NetworkBg
        // shows through), glass card, logo box.
        let mut cv = self.ui.view(cx, ids!(connect_view));
        script_apply_eval!(cx, cv, {
            draw_bg +: { color: #x00000000 }
        });

        // 2b. Network background — recolor gradient + node/line instances.
        let mut nbg = self.ui.view(cx, ids!(network_bg));
        script_apply_eval!(cx, nbg, {
            draw_bg +: { grad_top: #(cgrad_top), grad_bot: #(cgrad_bot), node_color: #(cnode), line_color: #(cline) }
        });

        // 2c. Glass card (GaussRoundedView) — per-theme tint / glow border /
        // shadow. The transparent-but-not-fully so tint over the blurred bg is
        // what sells "frosted glass". cshadow: opaque black dark / soft
        // purple-grey light.
        let cshadow = if is_dark { vec4(0.0, 0.0, 0.0, 0.7) } else { vec4(0.54, 0.48, 0.62, 0.3) };
        let mut cc = self.ui.view(cx, ids!(connect_card));
        script_apply_eval!(cx, cc, {
            draw_bg +: { tint_color: #(celev), border_color: #(cglow), shadow_color: #(cshadow), fallback_color: #(celev) }
        });

        let mut lb = self.ui.view(cx, ids!(logo_box));
        script_apply_eval!(cx, lb, {
            draw_bg +: { color: #(caccent) }
        });
        let mut ll = self.ui.label(cx, ids!(logo_letter));
        script_apply_eval!(cx, ll, {
            draw_text +: { color: #(cbg) }
        });

        // 3. Text inputs (dialog fields + connection-bar server field).
        // Border-defined style (GitHub-dark): the fill blends with the card
        // (input = elev, no patch contrast), and a clearly visible 1px border
        // carries the field boundary. Default border is a legible mid-grey;
        // the saturated accent replaces it ONLY on focus. Fill contrast
        // (darker/brighter than the card) was tried and rejected — both read
        // as dirty grey or a floating box; blending + a real border is clean.
        let inputs = [
            ids!(url_input),
            ids!(pass_input),
            ids!(alias_input),
            ids!(server_input),
        ];
        for path in inputs {
            let mut inp = self.ui.text_input(cx, path);
            script_apply_eval!(cx, inp, {
                draw_bg +: { color: #(cinput), color_hover: #(cinput), color_focus: #(cinput), border_color: #(cinput_b), border_color_focus: #(caccent) }
                draw_text +: { color: #(cprimary), color_hover: #(cprimary), color_focus: #(cprimary), color_empty: #(cmuted) }
                draw_cursor +: { color: #(caccent) }
            });
        }

        // 4. Buttons — Connect is the full-width gradient CTA. bar_connect_btn
        // / theme_btn are the in-console variants. NOTE: dialog_theme_btn is now
        // the transparent overlay inside ThemeSwitch — it must stay transparent,
        // so it is NOT in this recolor array (the ThemeSwitch shader draws the
        // visible surface).
        let buttons = [
            (ids!(dialog_connect_btn), caccent, cacchov, cbg),
            (ids!(bar_connect_btn), caccent, cacchov, cbg),
            (ids!(theme_btn), cbar, crowhov, cprimary),
        ];
        for (path, bg, bg_hov, fg) in buttons {
            let mut btn = self.ui.button(cx, path);
            script_apply_eval!(cx, btn, {
                draw_bg +: { color: #(bg), color_hover: #(bg_hov) }
                draw_text +: { color: #(fg) }
            });
        }

        // 4b. Connect button gradient — magenta (accent) → deep violet
        // (btn_grad2), horizontal. Hover lifts BOTH gradient stops toward a
        // brighter pink (cacchov / a lightened btn_grad2) so the button visibly
        // brightens on hover — Button's built-in Animator drives the smooth 0→1
        // transition via self.hover, giving the "dynamic" feel. color_2_hover
        // must be set too or hover breaks the gradient (falls to default theme).
        let cbtn_hover2 = vec4(
            p.btn_grad2.x.min(1.0) + 0.12,
            p.btn_grad2.y.min(1.0) + 0.12,
            p.btn_grad2.z.min(1.0) + 0.12,
            1.0,
        );
        let mut cbtn = self.ui.button(cx, ids!(dialog_connect_btn));
        script_apply_eval!(cx, cbtn, {
            draw_bg +: { color: #(caccent), color_2: #(cbtn_grad2), color_hover: #(cacchov), color_2_hover: #(cbtn_hover2), gradient_fill_horizontal: 1.0 }
        });

        // Theme switch: drive its shader's is_dark instance (1.0 dark / 0.0
        // light) so the knob slides + sun/moon glyph swaps. The transparent
        // overlay Button keeps the dialog_theme_btn id; it has no label now so
        // the old set_text calls are dropped. theme_btn (console bar) keeps its
        // text toggle as before.
        let cisdark = if is_dark { 1.0 } else { 0.0 };
        let mut tsw = self.ui.view(cx, ids!(theme_switch));
        script_apply_eval!(cx, tsw, {
            draw_bg +: { is_dark: #(cisdark) }
        });
        let mode_label = if is_dark { "Light" } else { "Dark" };
        self.ui.button(cx, ids!(theme_btn)).set_text(cx, mode_label);

        // 5. Dialog text: error status, wordmark/tagline/title, field labels.
        // Field labels use Csecond (~7:1 on the card) instead of Cmuted, and
        // the compliance footer is now 11pt Csecond so it clears WCAG AA.
        let mut cs_lbl = self.ui.label(cx, ids!(connect_status));
        script_apply_eval!(cx, cs_lbl, {
            draw_text +: { color: #(p.danger) }
        });
        // Inline field errors: danger red, repainted every toggle so they stay
        // legible on either card surface.
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
        // Helper text under the password field stays muted — it's a hint, not
        // content, so Cmuted (~4.5:1) is the right weight.
        let mut ph = self.ui.label(cx, ids!(pass_helper));
        script_apply_eval!(cx, ph, {
            draw_text +: { color: #(cmuted) }
        });
        let dialog_labels = [
            (ids!(nyx_logo), cprimary),
            (ids!(connect_tagline), csecond),
            (ids!(url_label), csecond),
            (ids!(alias_label), csecond),
            (ids!(pass_label), csecond),
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
                    }
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
