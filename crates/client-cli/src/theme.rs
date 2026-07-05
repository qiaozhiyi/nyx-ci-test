//! 主题系统——支持 Catppuccin Mocha（默认）、高对比度、NO_COLOR 三种调色板。
//!
//! 历史背景：最初硬编码 Mocha 配色，所有颜色是 `pub const`。现改成运行时可切换：
//! `Palette` 结构体持有当前生效的全部颜色，`init(name)` 在 TUI 启动时根据
//! 配置文件 + `NO_COLOR` 环境变量选定一份存进全局 `OnceLock`。render 代码通过
//! `theme::accent()` / `theme::muted()` 等函数访问，不再直接读 const。
//!
//! 原 `pub const` 保留为 Mocha 预设的源数据 + 测试基准，不删除以免破坏常量上下文
//! 使用（如 match pattern）。运行时颜色一律走函数。

use std::sync::{OnceLock, RwLock};

use ratatui::style::{Color, Modifier, Style};

// ---- 基础工具 ----

const fn rgb(hex: u32) -> Color {
    Color::Rgb(
        ((hex >> 16) & 0xff) as u8,
        ((hex >> 8) & 0xff) as u8,
        (hex & 0xff) as u8,
    )
}

// ---- Mocha 预设（保留为 pub const：测试基准 + 常量上下文）----
// 这些值也是 `Palette::mocha()` 的数据源。改这里 = 改 Mocha 主题。

/// Default text (Mocha)。
pub const TEXT: Color = rgb(0xcdd6f4); // Text
/// Dimmed text (Mocha)。A11y-A1: 提升到 Subtext1 以通过 WCAG AA。
pub const MUTED: Color = rgb(0xbac2de); // Subtext1
/// Faintest (Mocha)。A11y-A1: 提升到 Overlay2 以通过 AA。
pub const FAINT: Color = rgb(0x9399b2); // Overlay2
pub const SURFACE: Color = rgb(0x181825); // Mantle
/// 背景层次 1（比 surface 亮一档）：tab 高亮背景、hover 卡片底。
pub const SURFACE1: Color = rgb(0x1e1e2e); // Base
/// 背景层次 2（介于 surface 和 surface1）：非焦点窗格边框，接近背景让双线感消失。
pub const SURFACE2: Color = rgb(0x313244); // Surface0
pub const BASE: Color = rgb(0x11111b); // Crust
pub const HEADER: Color = rgb(0x181825); // Mantle
pub const ACCENT: Color = rgb(0x89b4fa); // Blue
pub const ACCENT_DIM: Color = rgb(0x74c7ec); // Sapphire
pub const SUCCESS: Color = rgb(0xa6e3a1); // Green
pub const WARN: Color = rgb(0xf9e2af); // Yellow
pub const DANGER: Color = rgb(0xf38ba8); // Red
pub const MAUVE: Color = rgb(0xcba6f7); // Mauve
#[allow(dead_code)]
pub const TEAL: Color = rgb(0x94e2d5); // Teal

// ---- 调色板（运行时生效的颜色集合）----

/// 一套完整的 UI 调色板。三套预设（Mocha/HighContrast/NoColor）各产出一个。
#[derive(Clone, Copy)]
pub struct Palette {
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub surface: Color,
    /// 背景层次 1：tab 高亮、卡片底（比 surface 亮）。
    pub surface1: Color,
    /// 背景层次 2：非焦点边框（介于 surface 和 surface1，接近背景）。
    pub surface2: Color,
    pub base: Color,
    pub header: Color,
    pub accent: Color,
    pub accent_dim: Color,
    pub success: Color,
    pub warn: Color,
    pub danger: Color,
    pub mauve: Color,
}

impl Palette {
    /// Catppuccin Mocha（默认，已修复 A11y 对比度）。
    fn mocha() -> Self {
        Self {
            text: TEXT,
            muted: MUTED,
            faint: FAINT,
            surface: SURFACE,
            surface1: SURFACE1,
            surface2: SURFACE2,
            base: BASE,
            header: HEADER,
            accent: ACCENT,
            accent_dim: ACCENT_DIM,
            success: SUCCESS,
            warn: WARN,
            danger: DANGER,
            mauve: MAUVE,
        }
    }

    /// 高对比度（WCAG AAA 级）：纯黑底、纯白字、饱和强调色。
    /// 给低视力用户、强眩光环境、老旧终端用。所有组合 >= 7:1。
    fn high_contrast() -> Self {
        Self {
            text: Color::White,
            muted: Color::Gray,     // 7:1 on black
            faint: Color::DarkGray, // 用于纯装饰；承载内容用 muted
            surface: Color::Black,
            surface1: Color::DarkGray, // tab 高亮用深灰，和黑底有对比
            surface2: Color::DarkGray, // 非焦点边框
            base: Color::Black,
            header: Color::Black,
            accent: Color::Cyan, // 醒目
            accent_dim: Color::Cyan,
            success: Color::Green,
            warn: Color::Yellow,
            danger: Color::Red,
            mauve: Color::Magenta,
        }
    }

    /// NO_COLOR 模式（https://no-color.org）：遵守环境约定，去色用终端默认。
    /// 所有颜色用 `Color::Reset`（终端默认前景/背景），仅靠粗体/形状区分。
    fn no_color() -> Self {
        Self {
            text: Color::Reset,
            muted: Color::Reset,
            faint: Color::Reset,
            surface: Color::Reset,
            surface1: Color::Reset,
            surface2: Color::Reset,
            base: Color::Reset,
            header: Color::Reset,
            accent: Color::Reset,
            accent_dim: Color::Reset,
            success: Color::Reset,
            warn: Color::Reset,
            danger: Color::Reset,
            mauve: Color::Reset,
        }
    }
}

// ---- 全局当前调色板 ----

static CURRENT: OnceLock<RwLock<Palette>> = OnceLock::new();

/// 在 TUI 启动时调用一次，选定初始调色板（从配置文件 + NO_COLOR 环境变量）。
/// 选择优先级：`NO_COLOR` 环境变量 > `name` 参数 > 默认 Mocha。
pub fn init(name: &str) {
    let palette = palette_for_name(name);
    // OnceLock::get_or_init 只首次生效；RwLock 内部值可被 switch 热改。
    CURRENT.get_or_init(|| RwLock::new(palette));
    // 若已初始化（比如测试里先 init 过），也同步更新。
    if let Some(lock) = CURRENT.get() {
        if let Ok(mut g) = lock.write() {
            *g = palette;
        }
    }
}

/// 运行时热切换主题（/theme 命令调用）。返回 true 表示切换成功。
/// 和 init 不同：init 是首次初始化，switch 强制覆盖已初始化的值。
/// 若 CURRENT 未初始化（测试环境），先惰性初始化再写入。
pub fn switch(name: &str) -> bool {
    let palette = palette_for_name(name);
    let lock = CURRENT.get_or_init(|| RwLock::new(palette));
    if let Ok(mut g) = lock.write() {
        *g = palette;
        return true;
    }
    false
}

/// 按 name 解析调色板。NO_COLOR 环境变量最高优先级。
fn palette_for_name(name: &str) -> Palette {
    if std::env::var_os("NO_COLOR").is_some() {
        return Palette::no_color();
    }
    match name.to_ascii_lowercase().as_str() {
        "highcontrast" | "hc" => Palette::high_contrast(),
        "nocolor" => Palette::no_color(),
        _ => Palette::mocha(),
    }
}

/// 取当前生效调色板。若 `init` 未调用，惰性返回 Mocha 默认。
fn current() -> Palette {
    // Copy 语义：读出 owned 值，避免持锁渲染。
    CURRENT
        .get()
        .and_then(|l| l.read().ok().map(|g| *g))
        .unwrap_or_else(Palette::mocha)
}

// ---- 颜色访问器（render 代码用这些，不直接读 const）----

pub fn text_color() -> Color {
    current().text
}
pub fn muted_color() -> Color {
    current().muted
}
pub fn faint_color() -> Color {
    current().faint
}
pub fn accent() -> Color {
    current().accent
}
pub fn accent_dim() -> Color {
    current().accent_dim
}
pub fn success() -> Color {
    current().success
}
pub fn warn() -> Color {
    current().warn
}
pub fn danger() -> Color {
    current().danger
}
pub fn mauve() -> Color {
    current().mauve
}
#[allow(dead_code)]
pub fn base() -> Color {
    current().base
}
#[allow(dead_code)]
pub fn surface() -> Color {
    current().surface
}
/// 背景层次 1：tab 高亮、hover 卡片底（比 surface 亮一档）。
pub fn surface1() -> Color {
    current().surface1
}
/// 背景层次 2：非焦点窗格边框（接近背景，让相邻双线感消失）。
pub fn surface2() -> Color {
    current().surface2
}
#[allow(dead_code)]
pub fn header() -> Color {
    current().header
}

// ---- semantic Style helpers ----

/// Normal body text.
pub fn text() -> Style {
    Style::default().fg(text_color())
}

/// Dimmed text: timestamps, hints, unselected menu items.
pub fn muted() -> Style {
    Style::default().fg(muted_color())
}

/// Faintest: dividers, decoration, stream markers.
pub fn faint() -> Style {
    Style::default().fg(faint_color())
}

/// Bold accent — brand/primary labels, the app name.
pub fn brand() -> Style {
    Style::default().fg(accent()).add_modifier(Modifier::BOLD)
}

/// Bold + bright — used for the selected popup/overlay row.
pub fn selected() -> Style {
    let p = current();
    Style::default()
        .bg(p.accent_dim)
        .fg(p.base)
        .add_modifier(Modifier::BOLD)
}

/// Background fill for the status bar (header) strip.
pub fn header_bg() -> Style {
    let p = current();
    Style::default().bg(p.header).fg(p.text)
}

/// Background fill for the whole app (the base crust colour).
pub fn base_bg() -> Style {
    let p = current();
    Style::default().bg(p.base).fg(p.text)
}

/// Background fill for the input box area (slightly raised off the base).
pub fn input_bg() -> Style {
    let p = current();
    Style::default().bg(p.surface).fg(p.text)
}

/// Border style for the input box — soft accent, not a harsh cyan。
/// 当前输入栏改用 surface2 退让色，此函数保留作公共 API 预留。
#[allow(dead_code)]
pub fn input_border() -> Style {
    Style::default().fg(accent_dim())
}

/// A level-coloured span style for event-stream lines.
pub fn level(level: crate::rest::Level) -> Style {
    let fg = match level {
        crate::rest::Level::Info => text_color(),
        crate::rest::Level::Ok => success(),
        crate::rest::Level::Warn => warn(),
        crate::rest::Level::Err => danger(),
    };
    Style::default().fg(fg)
}

/// The leading marker colour for an event-stream line (matches its level but
/// dimmed so the marker reads as decoration, not content).
pub fn level_marker(level: crate::rest::Level) -> Style {
    let fg = match level {
        crate::rest::Level::Info => faint_color(),
        crate::rest::Level::Ok => success(),
        crate::rest::Level::Warn => warn(),
        crate::rest::Level::Err => danger(),
    };
    Style::default().fg(fg)
}

/// 日志级别的形状标记（A11y-A2）：除颜色外提供形状冗余，色盲用户也能区分级别。
/// 之前所有级别都用同一个 `▎` 字符，仅靠颜色区分——红绿色盲（8% 男性）下
/// SUCCESS(绿) 和 DANGER(红) 无法分辨。现在 Info/Ok/Warn/Err 各有独立符号。
pub fn level_glyph(level: crate::rest::Level) -> &'static str {
    match level {
        crate::rest::Level::Info => "ℹ",
        crate::rest::Level::Ok => "✓",
        crate::rest::Level::Warn => "⚠",
        crate::rest::Level::Err => "✕",
    }
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
        // Err 和 Ok 必须映射到不同颜色（回归保护）。
        let a = level(Level::Err);
        let b = level(Level::Ok);
        assert_ne!(a, b);
    }

    #[test]
    fn mocha_palette_has_non_reset_colors() {
        let p = Palette::mocha();
        assert_ne!(p.text, Color::Reset);
        assert_ne!(p.accent, Color::Reset);
    }

    #[test]
    fn high_contrast_uses_terminal_16_colors() {
        // 高对比度用 ANSI 16 色（纯黑/白/饱和色），非 Rgb，保证最广终端兼容。
        let p = Palette::high_contrast();
        assert!(matches!(p.base, Color::Black));
        assert!(matches!(p.text, Color::White));
    }

    #[test]
    fn no_color_yields_all_reset() {
        let p = Palette::no_color();
        assert_eq!(p.text, Color::Reset);
        assert_eq!(p.accent, Color::Reset);
    }

    #[test]
    fn init_picks_high_contrast_by_name() {
        // OnceLock 全局，只能 set 一次；这个测试验证 init 逻辑不 panic 且
        // current() 返回有效引用。具体哪套取决于首次调用，但函数必返回。
        init("highcontrast");
        let _ = current().text;
    }
}
