//! Catppuccin Mocha theme — the de-facto modern pastel terminal palette (used by
//! gitui, yazi, helix, etc.). All colors are explicit `Rgb` so the look is
//! identical across terminals instead of depending on the 16-colour ANSI map.
//!
//! Palette source: <https://catppuccin.com/palette/>. The semantic names below
//! map palette slots to UI roles so render code never touches raw hex.

use ratatui::style::{Color, Modifier, Style};

// ---- base palette (Catppuccin Mocha) ----

const fn rgb(hex: u32) -> Color {
    Color::Rgb(((hex >> 16) & 0xff) as u8, ((hex >> 8) & 0xff) as u8, (hex & 0xff) as u8)
}

/// Default text.
pub const TEXT: Color = rgb(0xcdd6f4); // Text
/// Dimmed text (timestamps, hints, placeholders).
pub const MUTED: Color = rgb(0x6c7086); // Subtext0
/// Faintest text (decoration, dividers).
pub const FAINT: Color = rgb(0x45475a); // Surface1
/// Surface background (panel body).
pub const SURFACE: Color = rgb(0x181825); // Mantle
/// Base background (app).
pub const BASE: Color = rgb(0x11111b); // Crust
/// Header / status-bar background.
pub const HEADER: Color = rgb(0x181825); // Mantle

// accents
pub const ACCENT: Color = rgb(0x89b4fa); // Blue — primary brand accent
pub const ACCENT_DIM: Color = rgb(0x74c7ec); // Sapphire
pub const SUCCESS: Color = rgb(0xa6e3a1); // Green
pub const WARN: Color = rgb(0xf9e2af); // Yellow
pub const DANGER: Color = rgb(0xf38ba8); // Red
pub const MAUVE: Color = rgb(0xcba6f7); // Mauve — secondary accent
/// Teal — palette slot, reserved for future widgets.
#[allow(dead_code)]
pub const TEAL: Color = rgb(0x94e2d5); // Teal

// ---- semantic Style helpers (the API render code actually uses) ----

/// Normal body text.
pub fn text() -> Style {
    Style::default().fg(TEXT)
}

/// Dimmed text: timestamps, hints, unselected menu items.
pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

/// Faintest: dividers, decoration, the `▎` stream markers at rest.
pub fn faint() -> Style {
    Style::default().fg(FAINT)
}

/// Bold accent — brand/primary labels, the app name.
pub fn brand() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

/// Bold + bright — used for the selected popup/overlay row.
pub fn selected() -> Style {
    Style::default().bg(ACCENT_DIM).fg(BASE).add_modifier(Modifier::BOLD)
}

/// Background fill for the status bar (header) strip.
pub fn header_bg() -> Style {
    Style::default().bg(HEADER).fg(TEXT)
}

/// Background fill for the whole app (the base crust colour).
pub fn base_bg() -> Style {
    Style::default().bg(BASE).fg(TEXT)
}

/// Background fill for the input box area (slightly raised off the base).
pub fn input_bg() -> Style {
    Style::default().bg(SURFACE).fg(TEXT)
}

/// Border style for the input box — soft accent, not a harsh cyan.
pub fn input_border() -> Style {
    Style::default().fg(ACCENT_DIM)
}

/// A level-coloured span style for event-stream lines.
pub fn level(level: crate::rest::Level) -> Style {
    use crate::rest::Level;
    let fg = match level {
        Level::Info => TEXT,
        Level::Ok => SUCCESS,
        Level::Warn => WARN,
        Level::Err => DANGER,
    };
    Style::default().fg(fg)
}

/// The leading marker colour for an event-stream line (matches its level but
/// dimmed so the marker reads as decoration, not content).
pub fn level_marker(level: crate::rest::Level) -> Style {
    use crate::rest::Level;
    let fg = match level {
        Level::Info => FAINT,
        Level::Ok => SUCCESS,
        Level::Warn => WARN,
        Level::Err => DANGER,
    };
    Style::default().fg(fg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb_unpacks_channels() {
        match rgb(0x89b4fa) {
            Color::Rgb(r, g, b) => {
                assert_eq!([r, g, b], [0x89, 0xb4, 0xfa]);
            }
            _ => panic!("expected Rgb"),
        }
    }

    #[test]
    fn level_colors_distinct_per_variant() {
        use crate::rest::Level;
        // Err and Ok must map to different colours (regression guard).
        let a = level(Level::Err);
        let b = level(Level::Ok);
        assert_ne!(a, b);
    }
}
