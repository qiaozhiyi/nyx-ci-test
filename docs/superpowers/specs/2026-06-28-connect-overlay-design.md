# Connect Overlay with Segmented Data-Flow Progress Bar

**Date:** 2026-06-28
**Status:** Approved (pending implementation)
**Scope:** `crates/client-ui/src/{main.rs,bridge.rs}` + live DSL
**Visual reference:** Option B "数据流分段" from brainstorm mockups

## 1. Problem

When the operator clicks Connect, two things happen with no transition:

1. The connect button (`dialog_connect_btn` / `bar_connect_btn`) stays at its
   default text and remains clickable — the operator can click again and fire
   duplicate concurrent `Cmd::Connect` requests.
2. On success the window jumps from 420×580 (login) to 1280×800 (console) in a
   single instantaneous `window.resize()` call (`main.rs:1384`), and the view
   flips. This is a jarring snap, not a smooth transition.

The bar-connect path has **no** feedback at all (`if !bar_connect` at
`main.rs:2014` skips the status update).

## 2. Goals

1. Show a full-window **overlay** during the entire connection attempt that
   masks the 420→1280 resize so the operator never sees the window snap.
2. The overlay carries an **indeterminate segmented data-flow progress bar**
   (option B) — 14 cells that light up green with a neon glow and travel left
   to right like packets flowing across a link.
3. On success the overlay briefly flashes green + fades out revealing the
   console. On failure it fades out returning to the connect form.
4. Prevent duplicate connect requests while an attempt is in flight.

## 3. Non-goals (YAGNI)

- No determinate percentage (connection duration is unknown — an indeterminate
  bar is the honest UX per [UX Planet best practice #4][uxplanet]).
- No animated window resize (Makepad `window.resize()` is instantaneous at the
  platform layer; per-frame resize interpolation is out of scope and
  cross-platform inconsistent).
- No Rust `Animator`/`Ease` state machine (that API is unverified in this
  codebase — flagged by the comment at `main.rs:1444`). All animation uses the
  **already-verified** `self.draw_pass.time` shader path (precedent:
  `main.rs:117` NetworkBg).

[uxplanet]: https://uxplanet.org/progress-bar-design-best-practices-526f4d0a3c30

## 4. Architecture

Two coordinated changes: a **state field** added to the bridge `Snapshot`, and
an **overlay view** added to the live DSL.

### 4.1 Bridge state machine — `bridge.rs`

Add an explicit `connecting` field so the UI can distinguish "idle, not
connected" from "attempt in flight".

**`Snapshot` struct** (around `bridge.rs:48`): add
```rust
/// True while a Cmd::Connect attempt is in flight (between the Connect
/// command and the first fetch_sessions resolution). Drives the connect
/// overlay: shown while true, fades out when it flips false.
pub connecting: bool,
```

**Worker loop** (`bridge.rs:239`): add `let mut connecting = false;` alongside
`was_connected` (line 237).

**Transitions:**
| Event | Location | `connecting` |
|-------|----------|--------------|
| `Cmd::Connect` received | `bridge.rs:244` | → `true` |
| `fetch_sessions` returns `Ok` | `bridge.rs:584` (Ok branch) | → `false` |
| `fetch_sessions` returns `Err` | `bridge.rs:592` (Err branch) | → `false` |
| 20s timeout since connect attempt with no resolution | new guard at top of loop | → `false` + `log_push("! connect: timed out")` |

**Timeout guard** (new, at the top of the worker loop body): track
`connect_attempt_time: Option<Instant>`, set when `connecting` flips true. If
`connecting && connect_attempt_time.elapsed() > 20s`, force `connecting = false`
and log the timeout so the UI recovers from a wedged attempt.

**Snapshot construction:** every `take_snapshot(...)` call and the inline
`Snapshot {...}` literal at `bridge.rs:715` must pass the current `connecting`
value. `take_snapshot` signature gains a `connecting: bool` param.

### 4.2 Overlay view — live DSL in `main.rs`

Add a top-most overlay `SolidView` as a sibling of `connect_view` and
`main_view` in the live DSL tree, so it renders above both:

```makepad
connecting_overlay := SolidView {
    width: Fill, height: Fill
    visible: false          // flipped by apply_snapshot
    draw_bg.color: Cbg      // opaque #050505 — masks the resize snap
    flow: Down, align: {x: 0.5, y: 0.5}
    // label + segmented track (shader-driven, see §4.3)
}
```

The overlay contains:
1. A label: `[ ESTABLISHING LINK ]` (One Dark `info` color `#9CDCFE`).
2. The segmented progress bar (a single shader `View`, §4.3).
3. A status line: `Connecting…` + subtext `negotiating beacon channel`.

### 4.3 Segmented data-flow progress bar — shader

The progress bar is **one** `View{ show_bg:true }` whose `draw_bg` pixel fn
renders the 14-cell track and the flowing packet using `self.draw_pass.time`
(matching the NetworkBg precedent — no app-side animation code).

Pixel fn logic (GLSL-ish, matches existing NetworkBg style):
```
// cell geometry
let cells = 14
let cell_w = self.rect_size.x / cells
let gap = 1.5  // px gap between cells

// a "wave" position 0..1 traveling left→right, looping
let period = 1.4   // seconds for one full sweep
let wave = mod(self.draw_pass.time, period) / period   // 0..1

for each cell i in 0..cells:
    let cell_center = (i + 0.5) / cells      // 0..1
    // distance from wave head, wrapped → lights cells near the head
    let d = abs(cell_center - wave)
    let intensity = smoothstep(0.22, 0.0, d)  // 1 near head, 0 far
    // fill the cell rect with green * intensity, + glow
```

Glow via the verified `Sdf2d.glow(vec4(0.0, 0.8, 0.0, 1.0), 3.0)` call (green
`#00C800` × intensity). The track background is the dark `#1a1a1a`.

**Success/fail tint** is driven by an `instance` float `done` (0 = connecting,
1 = success) and `failed` (0/1) set from Rust via `set_uniform`-style
`script_apply_eval!`:
- `connecting`: green packets flowing (default).
- `success` (`done=1`): all cells snap to solid green, glow widens, then the
  whole overlay's opacity ramps 1→0 over ~400ms via `draw_pass.time`-derived
  `fade` uniform, after which `set_visible(false)`.
- `fail` (`failed=1`): cells go red `#F44336` briefly, then overlay fades out.

### 4.4 App wiring — `main.rs` Rust

**New `App` field:**
```rust
connecting: bool,   // mirror of last snap.connecting
```

**`apply_snapshot`** (around `main.rs:1379`): set `self.connecting =
snap.connecting`. Show the overlay **before** the resize when a transition into
connecting is detected:

```
if snap.connecting && !self.connecting_prev {
    // about to (possibly) resize — mask it
    self.ui.view(cx, ids!(connecting_overlay)).set_visible(cx, true);
}
self.connecting_prev = self.connecting;
```

The overlay must be visible **before** the `window.resize()` at line 1384 so it
covers the snap. Since the resize only fires on `connected:true` (success), and
`connecting` is `true` right up until that same snapshot flips it false, the
overlay is guaranteed visible during the transition.

**On success** (`snap.connected && !self.has_connected`): set overlay
`done=1`, let the shader fade it, then `set_visible(false)` after the fade
window (~450ms via a `Instant` timer or a frame counter). The existing resize +
view flip happen underneath, hidden by the overlay.

**On failure** (`!snap.connected && self.connecting_prev`): set overlay
`failed=1`, fade out, `set_visible(false)`, then the existing error-routing
logic (`main.rs:1393-1436`) shows inline errors on the connect form.

**`MatchEvent` connect handler** (`main.rs:1980`): guard against duplicate
trigger:
```rust
if self.connecting {
    return;  // attempt in flight — ignore further clicks
}
```
This makes the overlay the single source of truth for "can I click connect".

## 5. Data flow

```
click Connect
  → Cmd::Connect → worker: connecting=true
  → snapshot(connecting:true) → UI: show overlay, bar_connect button disabled
  → overlay: green packets flowing
worker fetch_sessions:
  Ok  → connecting=false, connected=true
        → snapshot(connecting:false, connected:true)
        → UI: overlay done=1 (flash green+fade), window resize (hidden),
          view flip → console revealed
  Err → connecting=false, connected=false
        → snapshot(connecting:false, connected:false) + "! sessions: ..." log
        → UI: overlay failed=1 (red+fade), inline error on connect form
  >20s → connecting=false, "! connect: timed out" log → overlay failed=1 fade
```

## 6. Error handling

- Connection-refused / DNS / auth errors: unchanged routing
  (`apply_snapshot:1393-1436`) — they surface as inline field errors after the
  overlay fades.
- Wedged attempt (no fetch_sessions resolution ever): 20s timeout guard clears
  `connecting` and logs `"! connect: timed out"`, so the overlay can't get
  stuck open.
- Duplicate clicks: rejected by the `self.connecting` guard in `MatchEvent`.

## 7. Testing

Manual (no unit-test harness for the UI in this repo):
1. Point at a running server, click Connect → overlay appears with flowing
   green packets, console appears after fade. Window resize is invisible.
2. Point at a dead address, click Connect → overlay appears, then red flash +
   fade, inline "Could not reach server" error on the URL field.
3. During overlay, click Connect again → second click ignored (no duplicate
   `Cmd::Connect`).
4. Quick-reconnect bar (`bar_connect_btn`) → overlay also appears (fixes the
   current no-feedback bar path).
5. Wedge the worker (e.g. firewall that drops without RST) → after ~20s the
   overlay clears with a timeout message.

Build verification: `cargo build -p nyx-client-ui` passes on the host target.

## 8. Files touched

| File | Change |
|------|--------|
| `crates/client-ui/src/bridge.rs` | `Snapshot.connecting` field; worker `connecting` state + 20s timeout; thread `connecting` through all snapshot construction |
| `crates/client-ui/src/main.rs` | live DSL: `connecting_overlay` View + segmented-bar shader pixel fn; `App.connecting` field; `apply_snapshot` overlay show/hide + fade; `MatchEvent` duplicate-click guard |
| No `Cargo.toml` / `Cargo.lock` changes | shader + existing widgets only |

## 9. Design decisions & rationale

- **Indeterminate over determinate:** connection time is unknown; a fake 0→100%
  bar misleads ([UX Planet #4][uxplanet]). A flowing packet animation reads as
  "working" without promising a duration.
- **Shader over Rust Animator:** `self.draw_pass.time` is the **only** verified
  animation path in this codebase (NetworkBg). The Rust `Animator`/`Ease` API
  is explicitly flagged unverified (`main.rs:1444` comment). Staying in the
  shader layer keeps the change low-risk and matches the existing aesthetic.
- **Overlay masks resize, not animates it:** platform `window.resize()` is
  instantaneous and non-animatable. Hiding the snap behind an opaque overlay is
  the standard technique (VS Code, Slack) and works cross-platform.
- **Explicit `connecting` field over inference:** inferring "connecting" from
  `was_connected` edges can't distinguish "still trying" from "failed and idle"
  — that ambiguity is the root cause of the current no-feedback bar path.
- **20s timeout:** prevents a stuck-open overlay if `fetch_sessions` never
  resolves (e.g. dropped packets with no RST). Tunable; chosen as a generous
  upper bound for a LAN/localhost operator link.
