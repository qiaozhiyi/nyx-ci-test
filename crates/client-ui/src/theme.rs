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
            bg:      rgb(0x16, 0x16, 0x1E), // #16161E  app bg (deepest)
            panel:   rgb(0x1B, 0x1B, 0x26), // #1B1B26  side panels / log shell
            elev:    rgb(0x2D, 0x2D, 0x3D), // #2D2D3D  card / inputs / headers
            row:     rgb(0x1B, 0x1B, 0x26), // #1B1B26  table row base
            rowhov:  rgb(0x35, 0x35, 0x48), // #353548  row hover
            rowsel:  rgb(0x3A, 0x2A, 0x3E), // #3A2A3E  row selected (magenta tint)
            border:  rgb(0x3D, 0x3D, 0x50), // #3D3D50  hairline dividers (visible)
            bar:     rgb(0x1B, 0x1B, 0x26), // #1B1B26  recessed bars
            primary: rgb(0xD4, 0xD4, 0xD4), // #D4D4D4  primary text
            second:  rgb(0xAB, 0xAB, 0xB2), // #ABABB2  secondary text
            muted:   rgb(0x7F, 0x7F, 0x86), // #7F7F86  muted text
            accent:  rgb(0xC5, 0x86, 0xC0), // #C586C0  One Dark magenta
            acchov:  rgb(0xD8, 0x9E, 0xD4), // #D89ED4  accent hover
            success: rgb(0x4E, 0xC9, 0xB0), // #4EC9B0  teal
            danger:  rgb(0xF4, 0x47, 0x47), // #F44747  red
            warn:    rgb(0xDC, 0xDC, 0xAA), // #DCDCAA  warm yellow
            info:    rgb(0x9C, 0xDC, 0xFE), // #9CDCFE  light blue
        }
    }

    /// Light ramp — neutral paper; accent kept as a muted magenta so the
    /// theme toggle still reads as the same product family.
    pub fn light() -> Self {
        Palette {
            bg:      rgb(0xF5, 0xF5, 0xF8), // #F5F5F8
            panel:   rgb(0xFC, 0xFC, 0xFD), // #FCFCFD
            elev:    rgb(0xFF, 0xFF, 0xFF), // #FFFFFF
            row:     rgb(0xFC, 0xFC, 0xFD), // #FCFCFD
            rowhov:  rgb(0xEE, 0xEE, 0xF3), // #EEEEF3
            rowsel:  rgb(0xF3, 0xE9, 0xF1), // #F3E9F1
            border:  rgb(0xDD, 0xDD, 0xE4), // #DDDDE4
            bar:     rgb(0xED, 0xED, 0xF2), // #EDEDF2
            primary: rgb(0x2C, 0x2C, 0x38), // #2C2C38
            second:  rgb(0x5A, 0x5A, 0x68), // #5A5A68
            muted:   rgb(0x84, 0x84, 0x92), // #848492
            accent:  rgb(0xA8, 0x4A, 0x9E), // #A84A9E (muted magenta)
            acchov:  rgb(0xBD, 0x60, 0xB3), // #BD60B3
            success: rgb(0x1E, 0x8A, 0x73), // #1E8A73
            danger:  rgb(0xC4, 0x33, 0x33), // #C43333
            warn:    rgb(0x8A, 0x6D, 0x1E), // #8A6D1E
            info:    rgb(0x2A, 0x6E, 0xA8), // #2A6EA8
        }
    }
}
