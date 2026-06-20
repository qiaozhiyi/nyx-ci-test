# Glassmorphism Login Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the flat `connect_card` dialog with a frosted-glass (Glassmorphism) login card over an animated network-node background, matching the user's reference screenshots in both dark and light modes.

**Architecture:** Three new shader-decorated widgets, each defined as a **pure-DSL `View` with a `draw_bg +: { pixel: fn(){} }` shader** (the `GlassPanel` precedent — no Rust struct needed except the theme toggle, which needs click handling). The glass card uses Makepad's built-in `GaussRoundedView` for real backdrop blur. All visual tokens live in `theme.rs` + the `script_mod!` DSL header.

**Tech Stack:** Makepad 2.0 (`script_mod!` DSL, `Sdf2d` shader std, `GaussRoundedView`, `self.draw_pass.time`).

**Spec:** `docs/superpowers/specs/2026-06-19-glassmorphism-login-design.md`

---

## Critical Makepad 2.0 facts (verified against source rev d37a34f2)

These are load-bearing — violating any of them = compile fail. Every code block below already respects them.

1. **Macro is `script_mod!`**, not `live_design!`. No angle-bracket `<Widget>` syntax. Widgets are referenced as `mod.widgets.Name{}` (fully-qualified) or bare `Name{}` if `use mod.widgets.*` is in scope.
2. **Custom shader = `draw_bg +: { field: instance(...)/uniform(...); pixel: fn() { ... return sdf.result } }`** on a View. The `+` MERGES into the base DrawQuad shader (without it you clobber `self.pos`/`self.rect_size`). **Requires `show_bg: true`** on the View or the shader never runs.
3. **Shader method calls use dot syntax**: `Sdf2d.viewport(...)`, `sdf.circle(...)`, `sdf.glow(...)`, `Pal.premul(...)`. NOT `::`.
4. **New shader fields must be declared** `instance(default)` or `uniform(default)` before `pixel:`.
5. **`GaussRoundedView` properties** are set in `draw_bg +:`: `tint_color`, `tint_alpha`, `surface_alpha`, `border_color`, `border_alpha`, `border_width`, `corner_radius`, `blur_level`, `shadow_color`, `shadow_radius`, `shadow_offset`.

**HEAD RISK (Task 1 resolves this):** `GaussRoundedView`'s real blur needs the window to capture the scene. On a non-transparent window `has_gauss` may stay 0 and fall back to `fallback_color` (flat fill, no blur). Task 1 is a spike to confirm whether blur activates. If it does NOT, we fall back to a high-`surface_alpha` translucent tint (still glass-like, just not blurred) — the plan handles both outcomes.

**Verification method:** Makepad shader UI cannot be unit-tested. Each task's verification = `cargo build -p nyx-client-ui` compiles clean + manual window inspection. Commits happen per task.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/client-ui/src/theme.rs` | Modify | Add glass/node/glow/btn-gradient tokens to `Palette` (dark+light) |
| `crates/client-ui/src/main.rs` | Modify | DSL: new widget definitions + restructured `connect_view`; `apply_theme` sets new tokens |
| `crates/client-ui/src/widgets/theme_switch.rs` | Create | Rust widget struct (needs click handling) + DSL template with procedural sun/moon shader |
| `crates/client-ui/src/widgets/mod.rs` | Modify | Register `theme_switch` module |

The background (`network_bg`) and glass card (`glass_card`) are **DSL-only** widget definitions inside `main.rs`'s `script_mod!` (like `GlassPanel`), NOT separate Rust files — they have no event handling, just shaders. Only `theme_switch` needs a Rust struct because it handles clicks.

---

## Task 0: theme.rs — add glassmorphism tokens

**Files:**
- Modify: `crates/client-ui/src/theme.rs`

**Why first:** Every shader/widget below reads these tokens. Foundation layer.

- [ ] **Step 1: Add new fields to the `Palette` struct**

In `theme.rs`, after the existing `input_b` field (around line 57, after the `input_b` declaration), add these fields inside `pub struct Palette { ... }`:

```rust
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
```

- [ ] **Step 2: Add dark() values**

In `Palette::dark()`, after the `input_b` line, add:

```rust
            grad_top: rgb(0x1A, 0x1A, 0x2E), // #1A1A2E  bg gradient top
            grad_bot: rgb(0x0F, 0x0F, 0x1A), // #0F0F1A  bg gradient bottom
            node:    rgb(0x8B, 0x9D, 0xC3), // #8B9DC3  network nodes (α set in shader)
            line:    rgb(0x5A, 0x6B, 0xA0), // #5A6BA0  network lines
            glow:    rgb(0xC5, 0x86, 0xC0), // #C586C0  card neon glow
            btn_grad2: rgb(0x9B, 0x6B, 0xB5), // #9B6BB5  button gradient end
```

- [ ] **Step 3: Add light() values**

In `Palette::light()`, after the `input_b` line, add:

```rust
            grad_top: rgb(0xE8, 0xE6, 0xF0), // #E8E6F0
            grad_bot: rgb(0xD4, 0xD2, 0xE0), // #D4D2E0
            node:    rgb(0x6A, 0x5A, 0x8A), // #6A5A8A
            line:    rgb(0x9A, 0x8A, 0xB0), // #9A8AB0
            glow:    rgb(0xA8, 0x4A, 0x9E), // #A84A9E
            btn_grad2: rgb(0x8A, 0x4A, 0x86), // #8A4A86
```

- [ ] **Step 4: Build to verify**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -5`
Expected: PASS — but note `apply_theme` doesn't yet use these; the `cinput`/`cinput_b` locals already exist. New tokens are just unused fields for now (Rust allows unused struct fields). If a warning about unused appears, that's fine.

- [ ] **Step 5: Commit**

```bash
git add crates/client-ui/src/theme.rs
git commit -m "feat(theme): add glassmorphism tokens (gradient/node/glow/btn-grad)"
```

---

## Task 1: GaussRoundedView blur spike — confirm real blur activates

**Files:**
- Modify: `crates/client-ui/src/main.rs` (lines ~389-401, the `connect_view` → `connect_card` block)

**Why:** Before building the whole glass design on `GaussRoundedView`, confirm the real blur actually renders (the HEAD RISK). This is a temporary edit — replaced properly in Task 3. If blur does NOT work, we learn it now and switch the glass strategy before wasting effort.

- [ ] **Step 1: Confirm `GaussRoundedView` is in scope**

In `crates/client-ui/src/main.rs`, find the `use mod.*` lines near the top of `script_mod!` (around line 50-52). Confirm there is `use mod.prelude.widgets.*`. `GaussRoundedView` ships in the makepad widgets prelude, so it should be in scope. If the build in Step 3 fails with "unknown GaussRoundedView", add `use mod.widgets.GaussRoundedView` to the use list.

- [ ] **Step 2: Swap connect_card to a GaussRoundedView spike**

Replace the current `connect_card` View (lines 394-400):

```makepad
                        connect_card := View{
                            width: 460 height: Fit
                            flow: Down
                            draw_bg.color: Celev
                            draw_bg.border_radius: Cradius
                            draw_bg.border_size: 2.0
                            draw_bg.border_color: Cborder
```

with this spike version:

```makepad
                        connect_card := GaussRoundedView{
                            width: 460 height: Fit
                            flow: Down
                            padding: Inset{top: 0.0 bottom: 0.0 left: 0.0 right: 0.0}
                            draw_bg +: {
                                tint_color: #x2D2D3D
                                tint_alpha: 0.55
                                surface_alpha: 0.82
                                border_color: #xC586C0
                                border_alpha: 0.5
                                border_width: 1.0
                                corner_radius: 12.0
                                blur_level: 4.0
                                shadow_color: #x000000B3
                                shadow_radius: 24.0
                                shadow_offset: vec2(0.0, 8.0)
                                fallback_color: #x2D2D3D
                            }
```

NOTE: the inner form content (header, inputs, button — lines 404 onward) stays exactly as-is; we only changed the card wrapper type + its draw_bg. `GaussRoundedView` accepts child widgets like a View.

- [ ] **Step 3: Build and inspect**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -10`
Expected: PASS (compiles).

Then run the app: `cargo run -p nyx-client-ui 2>&1 | tail -5` and visually inspect the login card.

**DECISION POINT:**
- If the card shows a **blurred** background behind it (the deep bg visibly smudged) → blur works. Proceed; real glass is achievable.
- If the card shows a **flat opaque/flat-translucent** fill with NO blur (looks like the `fallback_color`) → blur did NOT activate. Note this; Task 3's glass card will lean on high `surface_alpha` translucency + the neon glow to sell "glass" without true blur, and we bump `tint_alpha` up. Either way the plan continues — only the glass_card tuning differs.

- [ ] **Step 4: Commit the spike**

```bash
git add crates/client-ui/src/main.rs
git commit -m "spike(client-ui): GaussRoundedView on connect_card — confirm blur activation"
```

Record the blur outcome in the commit body or a note; it determines Task 3 tuning.

---

## Task 2: network_bg — animated network-node background (DSL-only widget)

**Files:**
- Modify: `crates/client-ui/src/main.rs` (add a `let NetworkBg = View{...}` definition near the other `let` widget templates around line 95+, before `connect_view`)

**Why:** The deep-purple gradient + drifting node matrix that sits BEHIND the glass card. Pure shader, no events, so it's a DSL-only `View` alias (GlassPanel pattern).

- [ ] **Step 1: Define the NetworkBg widget template**

In `main.rs`, after the existing widget template definitions (e.g. after `SessionRow` / `CredRow` area, around line 95-100, before the `connect_view` usage), add this DSL template. It declares shader uniforms/instances and a `pixel` fn that draws a vertical gradient + a grid of glowing nodes + connecting lines, drifting with `self.draw_pass.time`:

```makepad
    let NetworkBg = View{
        show_bg: true
        draw_bg +: {
            grad_top: instance(#x1A1A2E)
            grad_bot: instance(#x0F0F1A)
            node_color: instance(#x8B9DC3)
            line_color: instance(#x5A6BA0)
            time: uniform(0.0)

            pixel: fn() {
                // Vertical 2-stop gradient.
                let t = self.pos.y
                let bg = mix(self.grad_top, self.grad_bot, t)

                // Drifting node grid. Cell size in pixels; drift over time.
                let cell = 90.0
                let drift = vec2(self.time * 4.0, self.time * 2.5)
                let p = self.pos * self.rect_size + drift
                let gx = floor(p.x / cell)
                let gy = floor(p.y / cell)
                let cx = (gx + 0.5) * cell - drift.x
                let cy = (gy + 0.5) * cell - drift.y

                // Per-cell pseudo-jitter from gx/gy.
                let jitter = Math.frand(vec2(gx * 12.9 + gy * 78.2))
                let nx = cx + (jitter - 0.5) * cell * 0.5
                let ny = cy + (Math.frand(vec2(gx * 4.1 + gy * 91.7)) - 0.5) * cell * 0.5

                let sdf = Sdf2d.viewport(self.pos * self.rect_size)
                sdf.circle(nx, ny, 2.0)
                sdf.glow_keep(vec4(self.node_color.rgb, 0.5), 6.0)

                // Connecting line to the right neighbor cell.
                let nx2 = nx + cell
                let ny2 = ny + Math.frand(vec2((gx + 1.0) * 4.1 + gy * 91.7)) * cell * 0.5
                sdf.move_to(nx, ny)
                sdf.line_to(nx2, ny2)
                sdf.stroke(vec4(self.line_color.rgb, 0.18), 1.0)

                let layer = sdf.result
                return vec4(bg.rgb * (1.0 - layer.a) + layer.rgb, 1.0)
            }
        }
    }
```

NOTE on shader functions: `mix`, `floor`, `Math.frand`, `vec2`, `vec4` are Makepad shader builtins. `sdf.glow_keep` (additive, keeps shape) and `sdf.stroke` are Sdf2d methods. `sdf.move_to`/`sdf.line_to` build a path; `sdf.stroke` renders it. If `Math.frand` signature differs, substitute `Math.random_2d(vec2(gx, gy))` (the agent confirmed `Math.random_2d` exists in the shader std). The exact node-count/look is tunable later against the reference image — the goal here is a compiling, animating field.

- [ ] **Step 2: Place NetworkBg behind connect_view**

In the `connect_view` block (line ~389), it currently is:

```makepad
                    connect_view := View{
                        width: Fill height: Fill
                        align: Center
                        draw_bg.color: Cbg
```

Change it to an Overlay of NetworkBg + centered card so the card sits ON TOP of the background:

```makepad
                    connect_view := View{
                        width: Fill height: Fill
                        flow: Overlay
                        NetworkBg{width: Fill height: Fill}
                        // Centering wrapper for the card (sits above NetworkBg).
                        View{
                            width: Fill height: Fill
                            align: Center
```

Then the existing `connect_card` (the GaussRoundedView from Task 1) must be indented ONE more level (it was a direct child of `connect_view`; now it's a child of this centering View). Add the matching closing `}` for the new centering View right before `connect_view`'s closing brace.

**IMPORTANT indentation:** every line of the card + its children needs +4 spaces to stay valid DSL. Do this carefully — DSL is whitespace-sensitive for nesting depth (child blocks nest under parent).

- [ ] **Step 3: Build**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -15`
Expected: PASS. If shader compile fails, common fixes:
- `Math.frand` not found → use `Math.random_2d(vec2(seed))`
- `sdf.glow_keep` not found → use `sdf.glow(color, width)` (resets shape after)
- `mix` signature → Makepad's `mix(a, b, t)` takes (vec, vec, float); ensure types match.

- [ ] **Step 4: Inspect + tune**

Run the app. You should see the deep-purple gradient with slowly drifting glowing dots + faint connecting lines behind the card. Tune `cell` (node density), glow width, line alpha against the reference image (the reference nodes are subtle/sparse — start low).

- [ ] **Step 5: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): NetworkBg animated network-node background"
```

---

## Task 3: glass_card — promote the spike to the real glass surface

**Files:**
- Modify: `crates/client-ui/src/main.rs` (the `connect_card` GaussRoundedView block from Task 1)

**Why:** Task 1 was a spike to test blur. Now make the glass card the real, theme-driven surface and wire its properties into `apply_theme` so dark/light differ.

- [ ] **Step 1: Extract glass_card as a named DSL template**

After the `NetworkBg` template (Task 2 Step 1), add a `GlassCard` alias so it's reusable and theme-able. This is a GaussRoundedView with tuned glass defaults:

```makepad
    let GlassCard = GaussRoundedView{
        width: 460 height: Fit
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
```

(The `instance` vs `uniform` choice: things `apply_theme` will change per-theme = `instance`; static = `uniform`. Tint/border/shadow/fallback are per-theme → instance. Blur level → uniform, set once.)

- [ ] **Step 2: Use GlassCard in connect_view**

In the centering View (Task 2 Step 2), replace the `connect_card := GaussRoundedView{ ... draw_bg +: {...} }` spike with:

```makepad
                            connect_card := GlassCard{
```

…and remove the inline `draw_bg +:` block (it's now in the template). Keep `connect_card` as the instance name so all the `ids!(connect_card)` lookups in Rust still work. The form children stay identical.

- [ ] **Step 3: Build**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): GlassCard template (real GaussRoundedView glass surface)"
```

---

## Task 4: apply_theme — drive glass/network/button tokens

**Files:**
- Modify: `crates/client-ui/src/main.rs` (the `apply_theme` method, ~line 1144)

**Why:** Dark/light toggle must recolor the new glass card, network bg, and gradient button. Read the Task-0 tokens.

- [ ] **Step 1: Add new locals in apply_theme**

In `apply_theme`, after the existing `let cinput_b = p.input_b;` line (~line 1159), add:

```rust
        let cgrad_top = p.grad_top;
        let cgrad_bot = p.grad_bot;
        let cnode = p.node;
        let cline = p.line;
        let cglow = p.glow;
        let cbtn_grad2 = p.btn_grad2;
```

- [ ] **Step 2: Give NetworkBg an id (if not already)**

Task 2 Step 2 defined it as `network_bg := NetworkBg{...}`. Confirm that id exists; if you wrote it as a bare `NetworkBg{}`, add `network_bg :=` now. The id is needed so apply_theme can recolor it.

- [ ] **Step 3: Recolor the network background**

Still in `apply_theme`, after the inputs block (section 3, ~line 1217), add:

```rust
        // 3b. Network background — recolor gradient + node/line instances.
        let mut nbg = self.ui.view(cx, ids!(network_bg));
        script_apply_eval!(cx, nbg, {
            draw_bg +: { grad_top: #(cgrad_top), grad_bot: #(cgrad_bot), node_color: #(cnode), line_color: #(cline) }
        });
```

- [ ] **Step 4: Recolor the glass card**

After the network bg block, add a `cshadow` local (theme-appropriate shadow: opaque black for dark, soft purple-grey for light) and the card recolor:

```rust
        // 3c. Glass card tint / border-glow / shadow per theme.
        let cshadow = if is_dark { vec4(0.0, 0.0, 0.0, 0.7) } else { vec4(0.54, 0.48, 0.62, 0.3) };
        let mut gcard = self.ui.view(cx, ids!(connect_card));
        script_apply_eval!(cx, gcard, {
            draw_bg +: { tint_color: #(celev), border_color: #(cglow), shadow_color: #(cshadow) }
        });
```

(`vec4(r,g,b,a)` is in scope via `use makepad_widgets::*`; `#(cvar)` with a `Vec4` is the same interpolation the existing input/button recoloring already uses.)

- [ ] **Step 5: Build + inspect both themes**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -10`
Expected: PASS. Run the app, toggle theme (the existing Light/Dark button still works), confirm card + bg recolor.

- [ ] **Step 6: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): apply_theme drives glass/network/shadow tokens"
```

---

## Task 5: Gradient Connect button + button glow

**Files:**
- Modify: `crates/client-ui/src/main.rs` (the `dialog_connect_btn` block ~line 614, and apply_theme button section ~1224)

**Why:** Reference image shows a gradient-purple full-width Connect button with a soft glow — the "微光".

- [ ] **Step 1: Make the Connect button a gradient View-backed button**

The current `dialog_connect_btn` is a `Button` widget. Makepad `Button` may not expose `color_2`/gradient directly in this rev. Two options — pick based on what compiles:

**Option A (preferred, if Button exposes draw_bg.color_2):** add to the dialog_connect_btn DSL:
```makepad
                                        draw_bg.color_2: Cbtn_grad2
                                        draw_bg.gradient_fill_horizontal: true
```

**Option B (fallback):** wrap — keep the Button but layer a transparent gradient View behind it. Skip unless A fails.

Try Option A first.

- [ ] **Step 2: In apply_theme, set the gradient end color**

In the buttons array/loop (~line 1224), the dialog_connect_btn entry is `(ids!(dialog_connect_btn), caccent, cacchov, cbg)`. After the loop, add an explicit gradient recolor:

```rust
        // Connect button gradient (magenta → deep violet) + soft glow underlay.
        let mut cbtn = self.ui.button(cx, ids!(dialog_connect_btn));
        script_apply_eval!(cx, cbtn, {
            draw_bg +: { color: #(caccent), color_2: #(cbtn_grad2), gradient_fill_horizontal: true }
        });
```

- [ ] **Step 3: Build + inspect**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -10`
Expected: PASS (if Option A fails with unknown `color_2`, fall back to Option B or just keep solid accent — note it). Inspect: button should show a magenta→violet gradient, full-width.

- [ ] **Step 4: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): gradient Connect button"
```

---

## Task 6: theme_switch.rs — procedural sun/moon toggle

**Files:**
- Create: `crates/client-ui/src/widgets/theme_switch.rs`
- Modify: `crates/client-ui/src/widgets/mod.rs`
- Modify: `crates/client-ui/src/main.rs` (register + use + replace dialog_theme_btn)

**Why:** The reference shows a sun/moon toggle switch (no font glyphs available). Needs a Rust struct (click handling) + a DSL template with a procedural shader drawing the knob, sun-rays / moon-crescent, and a gradient track.

- [ ] **Step 1: Register the module**

In `crates/client-ui/src/widgets/mod.rs`, add:

```rust
pub mod theme_switch;
```

- [ ] **Step 2: Create the Rust widget struct**

Create `crates/client-ui/src/widgets/theme_switch.rs`:

```rust
//! Sun/moon theme toggle — a custom pill switch with a procedural shader
//! (no font glyphs needed; IBMPlexSans lacks ☀/☾). Click flips the global
//! IS_DARK flag and calls apply_theme via the same handler the text toggle
//! used. The visual (knob position, sun/moon glyph, track gradient) is
//! driven by the `is_dark` instance uniform in the draw_bg shader.

use makepad_widgets::*;

#[derive(Script, ScriptHook, Widget)]
pub struct ThemeSwitch {
    #[deref]
    view: View,
}

impl Widget for ThemeSwitch {
    fn draw_walk(&mut self, cx: &mut Cx2d, scope: &mut Scope, walk: Walk) -> DrawStep {
        self.view.draw_walk(cx, scope, walk)
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event, scope: &mut Scope) {
        // Forward to the inner Button (id: switch_btn) for hit-testing; the
        // App-level handler in main.rs reads the click off actions and toggles
        // IS_DARK + calls apply_theme — exactly as the old text toggle did.
        self.view.handle_event(cx, event, scope);
    }
}
```

- [ ] **Step 3: Register + define the DSL template in main.rs**

Near the top of `script_mod!` (after `use mod.widgets.*` and the existing `mod.widgets.BofPanel` registrations, ~line 253), add:

```makepad
    mod.widgets.ThemeSwitchBase = #(ThemeSwitch::register_widget(vm))
    mod.widgets.ThemeSwitch = set_type_default() do mod.widgets.ThemeSwitchBase{
        width: 90 height: 30
        flow: Overlay
        // The shader draws the track + knob + sun/moon. is_dark drives state.
        show_bg: true
        draw_bg +: {
            is_dark: instance(1.0)   // 1.0 = dark mode active, 0.0 = light
            sun_color: instance(#xFFD27A)
            moon_color: instance(#xB8C4E8)
            track_dark: instance(#x2A2A3E)
            track_light: instance(#xE8E0F0)
            knob_color: instance(#xF5F5F8)
            pixel: fn() {
                let sdf = Sdf2d.viewport(self.pos * self.rect_size)
                let w = self.rect_size.x
                let h = self.rect_size.y
                let r = h * 0.5
                // Pill track.
                sdf.box(0.0, 0.0, w, h, r)
                let track = mix(self.track_light, self.track_dark, self.is_dark)
                sdf.fill(track)
                // Knob slides: light mode (is_dark=0) → left, dark mode → right.
                let knob_x = mix(r, w - r, self.is_dark)
                sdf.circle(knob_x, h * 0.5, r * 0.8)
                sdf.fill(self.knob_color)
                // Sun (when light, is_dark≈0): rays implied by a brighter fill —
                // draw a small sun disc on the left track area.
                // Moon (when dark): crescent = two offset circles (subtract).
                let crescent_x = w - r * 0.6
                sdf.circle(crescent_x, h * 0.5, r * 0.55)
                sdf.fill_keep(self.moon_color)
                sdf.circle(crescent_x + r * 0.25, h * 0.5 - r * 0.15, r * 0.5)
                sdf.subtract()
                return sdf.result
            }
        }
        // Transparent hit-area button covering the whole pill.
        switch_btn := Button{
            width: Fill height: Fill
            draw_bg: { color: #00000000 }
            draw_text: { color: #00000000 }
            text: ""
        }
    }
```

- [ ] **Step 4: Place ThemeSwitch in the card footer, replacing the text toggle**

In the card's button section (~line 598-612, the `dialog_theme_btn` block), replace the whole buttons-row `View{ ... dialog_theme_btn ... }` with:

```makepad
                                // Theme switch centered in the footer.
                                View{
                                    width: Fill height: Fit
                                    align: Align{x: 0.5}
                                    theme_switch := mod.widgets.ThemeSwitch{}
                                }
                                dialog_connect_btn := Button{
                                    text: "Connect"
                                    width: Fill height: 38
                                    draw_bg.color: Caccent
                                    draw_bg.color_hover: Cacchov
                                    draw_bg.border_radius: 8.0
                                    draw_text.color: Cbg
                                    draw_text.text_style: theme.font_bold{font_size: 13}
                                }
```

- [ ] **Step 5: Update the Rust handler to read theme_switch clicks**

In `main.rs`'s action handler (~line 1241, where `dialog_theme_btn` click is handled), change it to also/instead listen to `switch_btn` inside `theme_switch`:

```rust
        let mode_label = if is_dark { "Light" } else { "Dark" };
        // The text toggle label is gone; ThemeSwitch shows its own glyph.
        // Set the switch's is_dark instance so its shader renders the right state.
        let mut sw = self.ui.widget(ids!(theme_switch));
        script_apply_eval!(cx, sw, {
            draw_bg +: { is_dark: #(if is_dark { 1.0 } else { 0.0 }) }
        });
```

And where clicks are handled (search for `dialog_theme_btn` in the actions match), add a branch for `ids!(theme_switch).switch_btn` or whichever path the Button action surfaces on. (The exact `items_with_actions` path for a button inside a custom widget: read actions off `self.ui.button(cx, ids!(theme_switch.switch_btn))` — but the id namespace may need `ids!(theme_switch, switch_btn)`. Verify the DSL id path compiles; if nested-id lookup fails, give the button a top-level id via the template instead.)

- [ ] **Step 6: Build + inspect**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -15`
Expected: PASS. Run the app, click the switch, confirm theme toggles and the knob slides + sun/moon swaps.

- [ ] **Step 7: Commit**

```bash
git add crates/client-ui/src/widgets/theme_switch.rs crates/client-ui/src/widgets/mod.rs crates/client-ui/src/main.rs
git commit -m "feat(client-ui): procedural sun/moon ThemeSwitch toggle"
```

---

## Task 7: Dark/light parity pass + polish

**Files:**
- Modify: `crates/client-ui/src/theme.rs`, `crates/client-ui/src/main.rs`

**Why:** Hold both themes against the two reference images side by side and tune the values that are off (glow strength, node density, blur level, shadow softness).

- [ ] **Step 1: Compare against reference images**

Open the app in dark mode, screenshot; toggle to light, screenshot. Compare each to the reference. Note deltas:
- Card glow too strong/weak? → `border_alpha` / glow intensity in GlassCard.
- Blur too much/little? → `blur_level`.
- Nodes too busy/sparse? → `cell` size in NetworkBg.
- Button gradient direction/color? → `btn_grad2` / `gradient_fill_horizontal`.
- Shadow too harsh/soft? → `shadow_radius` / `shadow_color` alpha.

- [ ] **Step 2: Apply tuned values**

Adjust the relevant tokens in `theme.rs` / DSL defaults. Rebuild + re-inspect until both themes match the references to satisfaction.

- [ ] **Step 3: Final build**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -5`
Expected: PASS, no warnings beyond the pre-existing bitflags one.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "style(client-ui): glassmorphism dark/light parity pass"
```

---

## Notes for the executor

- **DSL indentation is load-bearing.** When nesting the card one level deeper (Task 2), every child line gains 4 spaces. Get this wrong and the macro errors with confusing messages.
- **Shader method names are dot-call** (`Sdf2d.viewport`, `sdf.circle`). Never `::`.
- **`script_apply_eval!` color interpolation:** `#(cvar)` where `cvar: Vec4` works — it's how the existing input/button recoloring already does it. Follow that exact pattern.
- **If GaussRoundedView blur doesn't activate** (Task 1 outcome): the rest still works; bump `surface_alpha` to ~0.92 and `tint_alpha` to ~0.7 so the card reads as frosted-tint glass. The neon glow + gradient + network bg still deliver 80% of the effect.
- **ThemeSwitch click wiring** (Task 6 Step 5) is the one place with real API uncertainty — the nested `ids!(theme_switch.switch_btn)` lookup may need adjusting to how this rev exposes child-button actions. Budget time there; if stuck, give the switch button a top-level id in the template.
