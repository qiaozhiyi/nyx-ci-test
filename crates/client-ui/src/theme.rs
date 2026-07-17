//! Single source of truth for the Nyx client UI palette.
//!
//! Makepad's `script_mod!` DSL holds the *initial* (dark) palette as `#x` hex
//! tokens in `tokens.rs` (the `mod.nyx` namespace); this module is the *dynamic*
//! mirror consulted at draw time so the Light/Dark toggle stays consistent
//! everywhere (tables, dialog, bars) without a dozen hand-maintained copies of
//! the same color branches. `Palette::current()` reads the global
//! [`crate::IS_DARK`] and returns the matching ramp.
//!
//! The hex values in `tokens.rs` MUST mirror `Palette::dark()` so a cold first
//! paint already looks right before `apply_theme` runs. If you change a color
//! here, change its twin in the DSL — and vice-versa.
//!
//! Design notes
//! ------------
//! * Four discrete elevation steps (`bg` → `bar`/`panel` → `row` → `elev`) give
//!   real depth instead of a flat single-color wash. `bg` is the deepest surface
//!   (console/window); `elev` is the brightest (input fills, dialog card, column
//!   headers).
//! * The violet accent (`#8B7CF6`) is the single saturated hue — everything
//!   else is desaturated blue-charcoal. That is what makes it read as a pro
//!   tool: one signal, not a rainbow. (2026-07-16 reskin: One Dark magenta → violet.)
//! * `success` is soft teal (`#3FB68B`), `info` is light blue (`#5EB1EF`) — both used
//!   to colorize console output (process names, command keywords).
//! * Text contrast is tuned for readability against its surface: `primary`
//!   (#E2E4EA) ≈ 12:1, `muted` (#6B707E) ≈ 4.5:1 against `elev`/`panel`.

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
    /// Text/icons drawn ON the accent color (contrast pair for `accent`).
    pub onaccent: Vec4,
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

    /// Violet-dark pro-tool ramp (2026-07-16 reskin) — blue-tinted near-black
    /// surfaces with a single violet signal (`#8B7CF6`). Mirrors the `#x`
    /// tokens in main.rs script_mod!; change one, change both. Elevation steps
    /// (bg → panel → elev → border) are spread wide enough that the dialog
    /// card and panel headers read as distinct surfaces against the window.
    pub fn dark() -> Self {
        Palette {
            bg: rgb(0x0D, 0x0E, 0x12),        // #0D0E12  app bg (deepest)
            panel: rgb(0x14, 0x16, 0x1B),     // #14161B  side panels / log shell
            elev: rgb(0x1B, 0x1E, 0x26),      // #1B1E26  card / inputs / headers
            row: rgb(0x14, 0x16, 0x1B),       // #14161B  table row base
            rowhov: rgb(0x1F, 0x23, 0x30),    // #1F2330  row hover
            rowsel: rgb(0x2E, 0x28, 0x49),    // #2E2849  row selected (violet tint)
            border: rgb(0x26, 0x2A, 0x35),    // #262A35  hairline dividers
            bar: rgb(0x18, 0x1A, 0x21),       // #181A21  recessed bars
            input: rgb(0x1B, 0x1E, 0x26),     // #1B1E26  input fill (= card surface)
            input_b: rgb(0x3A, 0x3F, 0x4C),   // #3A3F4C  visible input border
            grad_top: rgb(0x0D, 0x0E, 0x12),  // #0D0E12  bg gradient top
            grad_bot: rgb(0x08, 0x09, 0x0C),  // #08090C  bg gradient bottom
            node: rgb(0x3A, 0x3F, 0x4C),      // #3A3F4C  network nodes (subtle)
            line: rgb(0x8B, 0x7C, 0xF6),      // #8B7CF6  network lines (violet)
            glow: rgb(0x8B, 0x7C, 0xF6),      // #8B7CF6  token kept; pro style uses no glow
            btn_grad2: rgb(0x6D, 0x5F, 0xD3), // #6D5FD3  token kept; buttons are solid now
            primary: rgb(0xE2, 0xE4, 0xEA),   // #E2E4EA  primary text
            second: rgb(0x9B, 0xA0, 0xAE),    // #9BA0AE  secondary text
            muted: rgb(0x6B, 0x70, 0x7E),     // #6B707E  muted text
            accent: rgb(0x8B, 0x7C, 0xF6),    // #8B7CF6  violet accent
            acchov: rgb(0xA3, 0x95, 0xFF),    // #A395FF  accent hover
            onaccent: rgb(0xFF, 0xFF, 0xFF),  // #FFFFFF  text/icons on accent
            success: rgb(0x3F, 0xB6, 0x8B),   // #3FB68B  soft teal-green
            danger: rgb(0xE5, 0x53, 0x4B),    // #E5534B  danger red
            warn: rgb(0xD9, 0xA0, 0x36),      // #D9A036  amber
            info: rgb(0x5E, 0xB1, 0xEF),      // #5EB1EF  light blue
        }
    }

    /// Light ramp — neutral paper; accent family swapped to violet so the
    /// theme toggle still reads as the same product (2026-07-16 reskin).
    pub fn light() -> Self {
        Palette {
            bg: rgb(0xD0, 0xD0, 0xD0),        // #D0D0D0
            panel: rgb(0xF0, 0xF0, 0xF0),     // #F0F0F0
            elev: rgb(0xEA, 0xEA, 0xEA),      // #EAEAEA
            row: rgb(0xFF, 0xFF, 0xFF),       // #FFFFFF
            rowhov: rgb(0xE8, 0xF0, 0xFA),    // #E8F0FA
            rowsel: rgb(0xD9, 0xD4, 0xF5),    // #D9D4F5  row selected (light violet tint)
            border: rgb(0xA0, 0xA0, 0xA0),    // #A0A0A0
            bar: rgb(0xE0, 0xE0, 0xE0),       // #E0E0E0
            input: rgb(0xFF, 0xFF, 0xFF),     // #FFFFFF
            input_b: rgb(0x80, 0x80, 0x80),   // #808080
            grad_top: rgb(0xF0, 0xF0, 0xF0),  // #F0F0F0
            grad_bot: rgb(0xD0, 0xD0, 0xD0),  // #D0D0D0
            node: rgb(0x9B, 0xA0, 0xAE),      // #9BA0AE
            line: rgb(0x6D, 0x5F, 0xD3),      // #6D5FD3
            glow: rgb(0x6D, 0x5F, 0xD3),      // #6D5FD3
            btn_grad2: rgb(0x58, 0x48, 0xB8), // #5848B8
            primary: rgb(0x00, 0x00, 0x00),   // #000000
            second: rgb(0x33, 0x33, 0x33),    // #333333
            muted: rgb(0x4F, 0x4F, 0x4F),     // #4F4F4F
            accent: rgb(0x6D, 0x5F, 0xD3),    // #6D5FD3  violet accent
            acchov: rgb(0x8B, 0x7C, 0xF6),    // #8B7CF6  accent hover
            onaccent: rgb(0xFF, 0xFF, 0xFF),  // #FFFFFF  text/icons on accent
            success: rgb(0x00, 0x80, 0x00),   // #008000
            danger: rgb(0xD1, 0x34, 0x38),    // #D13438
            warn: rgb(0xE3, 0x8B, 0x00),      // #E38B00
            info: rgb(0x00, 0x5A, 0x9C),      // #005A9C
        }
    }
}
