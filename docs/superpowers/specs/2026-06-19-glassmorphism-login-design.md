# Glassmorphism Login Card — Pixel-Accurate Replica

**Date:** 2026-06-19
**Status:** Approved (verbal "开始吧都没毛病")
**Scope:** Replace the current flat `connect_card` dialog with a frosted-glass
(Glassmorphism) login card over an animated network-node background, dark + light
modes, matching two reference screenshots provided by the user.

This is a **visual replica task**, not open-ended design. Every value below is
derived from the reference images + Makepad's confirmed render capabilities.

---

## 1. Goal & Non-Goals

**Goal:** The login screen (`connect_view` in `main.rs`) looks like the reference
images: a translucent frosted-glass card floating over a deep-purple gradient
background filled with an animated network-node matrix, neon-magenta glow on the
card edge, a full-width gradient-purple Connect button, and a custom sun/moon
theme-toggle switch — in both dark and light modes.

**Non-goals:**
- The connected **main console** (sessions / tables / event log) is OUT of scope.
  It keeps its current One Dark flat style. Glassmorphism is a login-scene treatment.
- No changes to auth/connect logic, form validation, or the bridge. Pure look.
- No new font loading. The sun/moon toggle is drawn procedurally (the current
  IBMPlexSans font lacks ☀/☾ glyphs — confirmed in existing code comments).

---

## 2. Feasibility — Makepad Capability Audit (verified against source rev d37a34f2)

All 7 required effects are supported. Evidence file paths are under
`~/.cargo/git/checkouts/makepad-ec2f134f34cd9f98/d37a34f2/`.

| Effect | Verdict | Mechanism |
|--------|---------|-----------|
| Frosted backdrop blur | ✅ 1:1 | `GaussRoundedView` (`widgets/src/gauss_view.rs`) — real scene capture + 13-tap gaussian over 6-mip chain |
| Translucent card | ✅ 1:1 | `draw_bg.color` alpha < 1.0 (premultiplied-alpha pipeline) |
| Card outer glow + shadow | ✅ 1:1 | `GaussRoundedView` ships a gaussian shadow; `sdf.glow()` (`draw/src/shader/sdf.rs:259`) for additive neon edge |
| Gradient button | ✅ 1:1 | View `color` + `color_2` + `gradient_fill_horizontal` (`view_ui.rs`) |
| Network-node bg | ✅ 1:1 | Custom `draw_bg.pixel` shader: SDF circle/line + `self.draw_pass.time` |
| Custom theme toggle | ✅ buildable | Custom shader-drawn slider + procedural sun/moon (no font glyph) |
| Animation | ✅ 1:1 | `self.draw_pass.time` uniform (shader-only) for the bg drift |

**Chosen glass path: real blur via `GaussRoundedView`** (user decision).
Login is the only fullscreen-blur scene; the per-frame scene-capture cost is
acceptable there and reverts when connected.

---

## 3. Architecture — New Widgets

Three new files in `crates/client-ui/src/widgets/`, registered in `mod.rs`.
Unlike the existing display widgets (BofPanel/CredTable etc. which are
virtualized lists over a global), these are **shader-decorated Views**: a thin
Widget shell (`#[derive(Script, ScriptHook, Widget)]` + `#[deref] view: View`)
whose DSL template carries the custom `draw_bg.pixel` shader.

### 3.1 `network_bg.rs` — Animated network-node background
- Full-`Fill` View behind everything in `connect_view`.
- Custom `draw_bg.pixel` shader draws:
  - A vertical 2-stop gradient (deep purple top → darker bottom).
  - A node matrix: N points on a jittered grid, drawn as small glowing dots via
    `sdf.circle` + `sdf.glow`.
  - Connecting lines between near-neighbor nodes via `sdf.line` (low alpha).
  - Slow drift driven by `self.draw_pass.time` (whole field translates/rotates
    a few px/sec — subtle, not distracting).
- Theme-able uniforms: `node_color`, `line_color`, `grad_top`, `grad_bottom`,
  `node_density`, `drift_speed`. Set from `apply_theme()` so dark/light differ.

### 3.2 `glass_card.rs` — Frosted card wrapper
- A `GaussRoundedView` subclass: real backdrop blur + its built-in gaussian
  shadow + a magenta `sdf.glow` edge pass.
- Exposes live props: `blur_level` (0–6), `tint_color` (the translucent fill),
  `tint_alpha`, `glow_color`, `glow_strength`, `shadow_color`, `shadow_radius`.
- The form content (logo / inputs / button) lives INSIDE this widget's DSL
  template as children; the card just provides the glass + glow surface.

### 3.3 `theme_switch.rs` — Sun/moon toggle
- A small pill (≈90×30) with a circular knob that slides left(right.
- Procedural shader draws: the knob as a circle, sun rays OR a crescent moon
  cutout depending on `is_dark` state, and a gradient track (warm-gold for light
  mode target, cool-indigo for dark).
- Click → toggles `IS_DARK` + calls `apply_theme()` (same path as today).
- Lives in the card footer, centered (matches reference image).

---

## 4. Visual Specification — Quantified

Values are estimates from the reference images, tuned to One Dark magenta
(`#C586C0`) as the existing accent so the result reads as the same product.

### 4.1 Background (network_bg)
| Token | Dark | Light |
|-------|------|-------|
| grad_top | `#1A1A2E` | `#E8E6F0` |
| grad_bottom | `#0F0F1A` | `#D4D2E0` |
| node_color | `#8B9DC3` @ α0.5 | `#6A5A8A` @ α0.4 |
| line_color | `#5A6BA0` @ α0.18 | `#9A8AB0` @ α0.15 |

### 4.2 Glass card (glass_card)
| Token | Dark | Light |
|-------|------|-------|
| tint_color | `#2D2D3D` | `#FFFFFF` |
| tint_alpha | 0.55 | 0.70 |
| blur_level | 4.0 | 3.0 |
| glow_color | `#C586C0` | `#A84A9E` |
| glow_strength | 0.6 | 0.35 |
| shadow_color | `#000000` @ α0.45 | `#8A7AA0` @ α0.25 |
| shadow_radius | 24.0 | 18.0 |
| border_radius | 12.0 | 12.0 |

### 4.3 Inputs (unchanged structure, restyled to sit on glass)
- Fill: same translucent tint as card (blend) — `#2D2D3D`/α0.4 dark, `#FFFFFF`/α0.6 light.
- Border: visible `#4A4A60` dark / `#D0D0DA` light, 1px; focus → magenta accent.
- Keep the existing field layout, labels, error/helper text, validation logic.

### 4.4 Connect button
- Full width (`width: Fill`), height 38, radius 8.
- Gradient: `#C586C0` → `#9B6BB5` (magenta → deeper violet), `gradient_fill_horizontal`.
- Text: inverted (`#FFFFFF`), bold, 13pt.
- Subtle `sdf.glow` underlay matching `glow_color` for the "微光" in the prompt.

### 4.5 Theme switch
- 90×30 pill, knob ⌀22. Track gradient warm↔cool by state.

---

## 5. Integration into main.rs

- `connect_view` becomes: `[NetworkBg full-Fill]` → overlay `[GlassCard centered]`
  → card children = existing logo/header/divider/inputs/button block, restyled
  per §4, with the text-button theme toggle **replaced** by `ThemeSwitch`.
- `apply_theme()` gains: set network_bg uniforms, glass_card tint/glow/shadow,
  button gradient, switch state. Reads `Palette::current()` (+ a few new tokens).
- `theme.rs`: add `glow`, `node`, `line`, `grad_top`, `grad_bot`, `btn_grad2`
  tokens to `Palette` (dark + light).
- DSL top-of-file `#x` tokens mirrored as today.
- `mod.rs`: register the 3 new widget modules.

The connected `main_view` (console) is untouched.

---

## 6. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| GaussRoundedView scene-capture perf on low-end GPU | Login-only; blur disabled once connected. `blur_level` tunable. |
| Custom shader compile errors (DSL shader syntax is finicky) | Build after each widget; reuse shapes from Makepad's SDF std + the `windows_blur` example as reference. |
| Network-node shader too busy / noisy | Start sparse (low α, few nodes), tune against the reference image which is subtle. |
| Sun/moon toggle interaction edge cases | Reuse the existing `IS_DARK` toggle path; widget just fires the same handler. |

---

## 7. Out of This Spec → Plan

Implementation order (detailed in the writing-plans phase):
1. `theme.rs` tokens + `mod.rs` registration (foundation).
2. `glass_card.rs` (the hero surface; biggest visual payoff first).
3. Re-skin the form inputs/button onto the glass card in `main.rs`.
4. `network_bg.rs` (background; independent, can iterate without touching card).
5. `theme_switch.rs` (replace text toggle).
6. Final dark/light parity pass + build.
