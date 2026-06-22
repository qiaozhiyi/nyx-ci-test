//! Single source of truth for the Nyx client UI palette.
//!
//! Makepad's `script_mod!` DSL holds the *initial* (dark) palette as `#x` hex
//! tokens in `main.rs`; this module is the *dynamic* mirror consulted at draw
//! time so the Light/Dark toggle stays consistent everywhere (tables, dialog,
//! bars) without a dozen hand-maintained copies of the same color branches.
//! `Palette::current()` reads the global [`crate::IS_DARK`] and returns the
//! matching ramp.
//!
//! The hex values in `script_mod!` (main.rs) MUST mirror `Palette::dark()` so a
//! cold first paint already looks right before `apply_theme` runs. If you change
//! a color here, change its twin in the DSL — and vice-versa.
//!
//! Design notes
//! ------------
//! * Four discrete elevation steps (`bg` → `bar`/`panel` → `row` → `elev`) give
//!   real depth instead of a flat single-color wash. `bg` is the deepest surface
//!   (console/window); `elev` is the brightest (input fills, dialog card, column
//!   headers).
//! * The One Dark magenta accent (`#C586C0`) is the single saturated hue —
//!   everything else is desaturated purple-charcoal. That is what makes it read
//!   as a pro tool: one signal, not a rainbow.
//! * `success` is teal (`#4EC9B0`), `info` is light blue (`#9CDCFE`) — both used
//!   to colorize console output (process names, command keywords) the way VS
//!   Code's One Dark syntax theme does.
//! * Text contrast is tuned for readability against its surface: `primary`
//!   (#CCCCCC) ≈ 10:1, `muted` (#8A8A8A) ≈ 4.5:1 against `elev`/`panel`.

use makepad_widgets::*;

/// The full color ramp the UI paints with. All fields are linear-ish sRGB in
/// `[0,1]`; Makepad composites them through the same pipeline as the DSL hex
/// tokens, so a value here and the matching `#xRRGGBB` in `main.rs` render
/// identically.
#[derive(Clone, Copy)]
pub struct Palette {
    /// App background — deepest surface (window clear color).
    pub bg: Vec4,
    /// Side panels and the event-log shell.
    pub panel: Vec4,
    /// Brightest surface — column-header rows, dialog card. One step up from panel.
    pub elev: Vec4,
    /// Table/data-row base.
    pub row: Vec4,
    /// Row hover.
    pub rowhov: Vec4,
    /// Row selected.
    pub rowsel: Vec4,
    /// Hairline borders / dividers.
    pub border: Vec4,
    /// Recessed secondary bars (tab bar, section headers).
    pub bar: Vec4,
    /// Text-input fill — SAME surface as the card (`elev`), so the field does
    /// NOT fight the card with a lighter/darker patch. This is the GitHub-dark
    /// input pattern: no fill contrast, the boundary is carried entirely by
    /// `input_b`. Fiddling with fill contrast (darker = grey patch, brighter =
    /// floating box) all read worse than just blending in.
    pub input: Vec4,
    /// Text-input default edge — a CLEARLY VISIBLE 1px line (not near-
    /// invisible). Because the fill blends with the card, the border IS the
    /// field boundary, so it must be legible at rest. Saturated accent still
    /// reserved for focus.
    pub input_b: Vec4,
    /// Network-bg gradient top.
    pub grad_top: Vec4,
    /// Network-bg gradient bottom.
    pub grad_bot: Vec4,
    /// Network-node dot color.
    pub node: Vec4,
    /// Network connecting-line color.
    pub line: Vec4,
    /// Card-edge neon glow color (magenta).
    pub glow: Vec4,
    /// Connect-button gradient end color (deeper violet).
    pub btn_grad2: Vec4,
    /// Primary text.
    pub primary: Vec4,
    /// Secondary text.
    pub second: Vec4,
    /// Muted / placeholder text.
    pub muted: Vec4,
    /// Signature cobalt accent.
    pub accent: Vec4,
    /// Accent hover.
    pub acchov: Vec4,
    /// Success / online / connected.
    pub success: Vec4,
    /// Danger / error / alert.
    pub danger: Vec4,
    /// Warning / pending.
    pub warn: Vec4,
    /// Info / command keyword (console highlighting). Light blue.
    pub info: Vec4,
}

/// Convenience: `Vec4(r,g,b,1.0)` from 8-bit channel values, matching the way
/// `#xRRGGBB` maps to floats in the rest of the codebase.
fn rgb(r: u8, g: u8, b: u8) -> Vec4 {
    vec4(r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0, 1.0)
}

impl Palette {
    /// The ramp for the current theme, chosen from the global [`crate::IS_DARK`].
    pub fn current() -> Self {
        if crate::IS_DARK.load(std::sync::atomic::Ordering::Relaxed) {
            Self::dark()
        } else {
            Self::light()
        }
    }

    /// One Dark Pro ramp — deep purple-charcoal with a pink-magenta signal.
    /// Mirrors the `#x` tokens in main.rs script_mod!; change one, change both.
    /// Elevation steps are spread wide enough (bg → panel → elev → border) that
    /// the dialog card and panel headers read as distinct surfaces against the
    /// window background — the v1 ramp was too tight and the card vanished.
    pub fn dark() -> Self {
        Palette {
            bg:      rgb(0x11, 0x11, 0x11), // #111111  app bg (deepest)
            panel:   rgb(0x1E, 0x1E, 0x1E), // #1E1E1E  side panels / log shell
            elev:    rgb(0x25, 0x25, 0x26), // #252526  card / inputs / headers
            row:     rgb(0x1E, 0x1E, 0x1E), // #1E1E1E  table row base
            rowhov:  rgb(0x2A, 0x2D, 0x2E), // #2A2D2E  row hover
            rowsel:  rgb(0x09, 0x47, 0x71), // #094771  row selected (cobalt blue)
            border:  rgb(0x33, 0x33, 0x33), // #333333  hairline dividers (visible)
            bar:     rgb(0x1E, 0x1E, 0x1E), // #1E1E1E  recessed bars
            input:   rgb(0x2D, 0x2D, 0x2D), // #2D2D2D  input fill
            input_b: rgb(0x55, 0x55, 0x55), // #555555  visible input border
            grad_top: rgb(0x11, 0x11, 0x11), // #111111  bg gradient top
            grad_bot: rgb(0x05, 0x05, 0x05), // #050505  bg gradient bottom
            node:    rgb(0x66, 0x66, 0x66), // #666666  network nodes
            line:    rgb(0x00, 0x7A, 0xCC), // #007ACC  network lines
            glow:    rgb(0x00, 0x7A, 0xCC), // #007ACC  card neon glow (changed to blue)
            btn_grad2: rgb(0x00, 0x50, 0xA0), // #0050A0  button gradient end
            primary: rgb(0xCC, 0xCC, 0xCC), // #CCCCCC  primary text
            second:  rgb(0xA0, 0xA0, 0xA0), // #A0A0A0  secondary text
            muted:   rgb(0x80, 0x80, 0x80), // #808080  muted text
            accent:  rgb(0x00, 0x7A, 0xCC), // #007ACC  Cobalt blue
            acchov:  rgb(0x00, 0x98, 0xFF), // #0098FF  accent hover
            success: rgb(0x00, 0xC8, 0x00), // #00C800  sharp hacker green
            danger:  rgb(0xF4, 0x43, 0x36), // #F44336  bright red
            warn:    rgb(0xFF, 0xC1, 0x07), // #FFC107  amber
            info:    rgb(0x56, 0x9C, 0xD6), // #569CD6  light blue
        }
    }

    /// Light ramp — neutral paper; accent kept as a muted magenta so the
    /// theme toggle still reads as the same product family.
    pub fn light() -> Self {
        Palette {
            bg:      rgb(0xD0, 0xD0, 0xD0), // #D0D0D0
            panel:   rgb(0xF0, 0xF0, 0xF0), // #F0F0F0
            elev:    rgb(0xEA, 0xEA, 0xEA), // #EAEAEA
            row:     rgb(0xFF, 0xFF, 0xFF), // #FFFFFF
            rowhov:  rgb(0xE8, 0xF0, 0xFA), // #E8F0FA
            rowsel:  rgb(0x3B, 0x72, 0xAB), // #3B72AB
            border:  rgb(0xA0, 0xA0, 0xA0), // #A0A0A0
            bar:     rgb(0xE0, 0xE0, 0xE0), // #E0E0E0
            input:   rgb(0xFF, 0xFF, 0xFF), // #FFFFFF
            input_b: rgb(0xA0, 0xA0, 0xA0), // #A0A0A0
            grad_top: rgb(0xF0, 0xF0, 0xF0), // #F0F0F0
            grad_bot: rgb(0xD0, 0xD0, 0xD0), // #D0D0D0
            node:    rgb(0x3B, 0x72, 0xAB), // #3B72AB
            line:    rgb(0xA0, 0xA0, 0xA0), // #A0A0A0
            glow:    rgb(0x3B, 0x72, 0xAB), // #3B72AB
            btn_grad2: rgb(0x2E, 0x5B, 0x8A), // #2E5B8A
            primary: rgb(0x00, 0x00, 0x00), // #000000
            second:  rgb(0x33, 0x33, 0x33), // #333333
            muted:   rgb(0x66, 0x66, 0x66), // #666666
            accent:  rgb(0x3B, 0x72, 0xAB), // #3B72AB
            acchov:  rgb(0x5B, 0x9B, 0xD5), // #5B9BD5
            success: rgb(0x00, 0x80, 0x00), // #008000
            danger:  rgb(0xD1, 0x34, 0x38), // #D13438
            warn:    rgb(0xE3, 0x8B, 0x00), // #E38B00
            info:    rgb(0x00, 0x5A, 0x9C), // #005A9C
        }
    }
}
