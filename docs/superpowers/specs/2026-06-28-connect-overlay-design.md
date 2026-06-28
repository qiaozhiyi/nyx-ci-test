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
3. **A live step-tip line below the bar** that reports the *real* connection
   stage in flight (resolving host / opening connection / authenticating), so
   the operator sees where the attempt is — not a fake cycling label.
4. On success the overlay briefly flashes green + fades out revealing the
   console. On failure it fades out returning to the connect form (and the
   step-tip tells the operator *which* stage failed).
5. Prevent duplicate connect requests while an attempt is in flight.

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
- No separation of TCP-connect and TLS-handshake into distinct observable
  stages. reqwest bundles both inside its `HttpConnector` and does not expose
  per-stage hooks without a custom hyper connector + `hyper-rustls` wrapper —
  a large, risky change for marginal diagnostic gain. They surface as a single
  "opening connection" stage (see §4.5).

[uxplanet]: https://uxplanet.org/progress-bar-design-best-practices-526f4d0a3c30

## 4. Architecture

Three coordinated changes: a **`connect_stage` field** added to the bridge
`Snapshot`, an **observable DNS resolver** wired into the reqwest client, and
an **overlay view** added to the live DSL.

### 4.1 Bridge state machine — `bridge.rs`

Add an explicit `connecting` flag **and a `connect_stage` enum** so the UI can
distinguish "idle, not connected" from "attempt in flight" and report *which*
stage the attempt is in.

**`Snapshot` struct** (around `bridge.rs:48`): add
```rust
/// True while a Cmd::Connect attempt is in flight (between the Connect
/// command and the first fetch_sessions resolution). Drives the connect
/// overlay: shown while true, fades out when it flips false.
pub connecting: bool,

/// The real connection stage currently in flight (or the last one reached).
/// Drives the step-tip line under the progress bar. See §4.5 for the model.
pub connect_stage: ConnectStage,
```

`ConnectStage` is a `Copy` enum defined alongside `Snapshot`:
```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ConnectStage {
    #[default]
    Idle,          // not connecting
    Resolving,     // DNS lookup in flight
    Connecting,    // TCP+TLS+request in flight (reqwest bundles these)
    Authenticating,// response received; decoding / awaiting session list
    Done,          // success
    Failed,        // attempt resolved with an error
}
```

**Worker loop** (`bridge.rs:239`): add `let mut connecting = false;` alongside
`was_connected` (line 237).

**Transitions:**
| Event | Location | `connecting` | `connect_stage` |
|-------|----------|--------------|-----------------|
| `Cmd::Connect` received | `bridge.rs:244` | → `true` | → `Resolving` |
| custom DNS resolver fires (§4.5) | inside the resolver's `resolve()` | (no change) | → `Connecting` |
| `fetch_sessions` returns `Ok` | `bridge.rs:584` (Ok branch) | → `false` | → `Done` |
| `fetch_sessions` returns `Err` | `bridge.rs:592` (Err branch) | → `false` | → `Failed` |
| 20s timeout, no resolution | new guard at top of loop | → `false` | → `Failed` + `log_push("! connect: timed out")` |

The stage is bumped **before** the stage's network call returns, and a snapshot
is pushed on each stage transition so the UI's step-tip updates promptly. A
helper `push_stage(&mut stage, &mut log_buf, to_ui, connecting, new)` advances
the stage and pushes a snapshot in one place — avoids scattered snapshot sends.

**Timeout guard** (new, at the top of the worker loop body): track
`connect_attempt_time: Option<Instant>`, set when `connecting` flips true. If
`connecting && connect_attempt_time.elapsed() > 20s`, force `connecting = false`
+ `connect_stage = Failed` and log the timeout so the UI recovers from a wedged
attempt.

**Snapshot construction:** every `take_snapshot(...)` call and the inline
`Snapshot {...}` literal at `bridge.rs:715` must pass the current `connecting`
and `connect_stage` values. `take_snapshot` signature gains
`connecting: bool, connect_stage: ConnectStage` params.

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

**Step-tip label** — a plain `Label` under the bar (live id `connect_step_tip`),
text color `#9CDCFE` (info). Its text is set from Rust each snapshot from the
`connect_stage` (§4.4). This is NOT part of the shader — it's a real Makepad
Label so text stays crisp and localizable.

### 4.4 App wiring — `main.rs` Rust

**New `App` fields:**
```rust
connecting: bool,          // mirror of last snap.connecting
connecting_prev: bool,     // edge detection for overlay show/hide
connect_stage: ConnectStage, // mirror of last snap.connect_stage
```

**`apply_snapshot`** (around `main.rs:1379`): set `self.connecting =
snap.connecting` and `self.connect_stage = snap.connect_stage`. Show the overlay
**before** the resize when a transition into connecting is detected, and refresh
the step-tip text:

```
if snap.connecting && !self.connecting_prev {
    // about to (possibly) resize — mask it
    self.ui.view(cx, ids!(connecting_overlay)).set_visible(cx, true);
}
self.connecting_prev = self.connecting;

// refresh the step-tip from the real stage
self.ui.label(cx, ids!(connect_step_tip))
    .set_text(cx, connect_stage_text(snap.connect_stage));
```

`connect_stage_text` maps the stage to operator-facing copy:
```rust
fn connect_stage_text(s: ConnectStage) -> &'static str {
    match s {
        ConnectStage::Idle          => "",
        ConnectStage::Resolving     => "resolving host…",
        ConnectStage::Connecting    => "opening connection…",
        ConnectStage::Authenticating=> "awaiting session list…",
        ConnectStage::Done          => "connected",
        ConnectStage::Failed        => "connection failed",
    }
}
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

### 4.5 Real connect-stage observability — the observable DNS resolver

This is the mechanism that makes the step-tip reflect *real* progress rather
than a fake time-cycling label. reqwest does not expose TCP/TLS sub-stages, but
it **does** let us plug a custom DNS resolver via
`ClientBuilder::dns_resolver(Arc<dyn Resolve>)` (`reqwest 0.12.28`,
`client.rs:2290`). The `Resolve` trait (`dns/resolve.rs:21`) has a single method
`fn resolve(&self, name: Name) -> Resolving`. We wrap the default resolver and
emit a stage transition when `resolve()` is called.

**Stage model (4 observable stages):**

| Stage | How observed | What it means |
|-------|-------------|---------------|
| `Resolving` | set when `Cmd::Connect` arrives (before the request fires) | about to / doing DNS lookup |
| `Connecting` | set inside the resolver's `resolve()` future, before awaiting the real lookup | DNS done (or cached); TCP+TLS+HTTP request in flight |
| `Authenticating` | set when `.send().await` returns but before `.json()` completes | server responded; decoding session list |
| `Done` / `Failed` | set from the `fetch_sessions` Ok/Err branches | terminal |

Why `Connecting` is set *inside* the resolver, not after: the resolver is
invoked as the first sub-step of reqwest's connector. Setting the stage there
means the moment DNS resolution begins we advance to "connection in flight",
which is the honest description of what reqwest is about to do (it will open the
socket + TLS next, with no further observable hook between). The resolver itself
performs the real lookup (we delegate to `GaiResolver`) and returns — we do not
synthesize addresses.

**`ObservingResolver` struct** (new, in `bridge.rs`):
```rust
/// Wraps the default getaddrinfo resolver; on each resolve() it bumps the
/// shared connect_stage to Connecting and notifies the worker loop, which
/// pushes a snapshot so the UI's step-tip updates. Implements reqwest::Resolve.
struct ObservingResolver {
    inner: Arc<dyn reqwest::dns::Resolve>,   // GaiResolver
    stage_tx: StageSender,                     // channel → worker loop
}
// resolve() delegates to inner.resolve(name) but first sends Connecting.
```

The worker builds its client with the resolver wired in:
```rust
let resolver = Arc::new(ObservingResolver::new(stage_tx));
let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(8))
    .dns_resolver(resolver)   // ← the hook
    .build()
    .expect("reqwest client build");
```

`Authenticating` is set in `fetch_sessions` right after `.send().await`
succeeds and before `.json().await`, so the brief decode window also reports a
stage. On a fast localhost link the stages may flash by in one frame — that's
fine and honest (the connection really was that quick); the stage mostly adds
value on slow/failing links where the operator sees it stuck on "resolving…"
or "opening connection…".

**Channel choice:** the resolver runs on reqwest's connector task; the worker
loop is the snapshot publisher. A `tokio::sync::mpsc` channel (non-blocking
try_recv in the loop, like the existing `cmd_rx`) carries `ConnectStage` updates
from resolver → worker. This matches the existing UI→worker command channel
pattern (`bridge.rs:241`).

## 5. Data flow

```
click Connect
  → Cmd::Connect → worker: connecting=true, stage=Resolving
  → snapshot(connecting:true, stage:Resolving) → UI: overlay visible, tip="resolving host…"
  reqwest connector calls ObservingResolver.resolve()
  → resolver sends stage=Connecting → worker → snapshot → tip="opening connection…"
  .send().await returns Ok → fetch_sessions sets stage=Authenticating
  → snapshot → tip="awaiting session list…"
  .json().await returns Ok → stage=Done, connecting=false, connected=true
        → snapshot(connecting:false, connected:true, stage:Done)
        → UI: overlay done=1 (flash green+fade), window resize (hidden),
          view flip → console revealed
  .send()/.json() Err → stage=Failed, connecting=false, connected=false
        → snapshot + "! sessions: ..." log
        → UI: overlay failed=1 (red+fade), tip="connection failed",
          inline error on connect form
  >20s no resolution → stage=Failed, connecting=false, "! connect: timed out"
        → overlay failed=1 fade
```

## 6. Error handling

- Connection-refused / DNS / auth errors: unchanged routing
  (`apply_snapshot:1393-1436`) — they surface as inline field errors after the
  overlay fades. The step-tip adds *which stage* failed (e.g. stuck on
  "resolving host…" = DNS failure; reached "awaiting session list…" then failed
  = auth/decode failure), giving the operator a faster diagnosis.
- Wedged attempt (no fetch_sessions resolution ever): 20s timeout guard clears
  `connecting`, sets `connect_stage = Failed`, and logs `"! connect: timed
  out"`, so the overlay can't get stuck open. The tip reads "connection failed".
- Duplicate clicks: rejected by the `self.connecting` guard in `MatchEvent`.
- Resolver stage signal lost: the channel is best-effort — if the
  `stage_tx→stage_rx` message is dropped (loop busy), the worker still advances
  `Connecting` via the resolver's side effect and reaches a terminal stage on
  `fetch_sessions` resolution. The tip may briefly lag but can't get stuck.

## 7. Testing

Manual (no unit-test harness for the UI in this repo):
1. Point at a running server, click Connect → overlay appears with flowing
   green packets, tip advances resolving → connecting → authenticating → done,
   console appears after fade. Window resize is invisible.
2. Point at a dead address, click Connect → overlay appears, tip shows
   "resolving host…" then "opening connection…", then red flash + fade, inline
   "Could not reach server" error on the URL field.
3. Point at an unresolvable host (`http://nonexistent.invalid:9999`) → tip
   sticks on "resolving host…" until the 8s reqwest timeout, then fails.
4. Point at a reachable host with a wrong API token → tip reaches "awaiting
   session list…" then fails with "Authentication failed" (existing 401
   routing), confirming the stage advanced past connection.
5. During overlay, click Connect again → second click ignored (no duplicate
   `Cmd::Connect`).
6. Quick-reconnect bar (`bar_connect_btn`) → overlay + tip also appear (fixes
   the current no-feedback bar path).
7. Wedge the worker (firewall that drops without RST) → after ~20s the overlay
   clears with a timeout message, tip reads "connection failed".

Unit-testable in isolation (no UI): the `ObservingResolver` can be tested by
giving it an in-memory `Resolve` stub and asserting it sends `Connecting` before
delegating. `connect_stage_text` is a pure fn — trivially unit-testable. These
go in `bridge.rs` under `#[cfg(test)]`.

Build verification: `cargo build -p nyx-client-ui` passes on the host target.

## 8. Files touched

| File | Change |
|------|--------|
| `crates/client-ui/src/bridge.rs` | `Snapshot.connecting` + `connect_stage` fields + `ConnectStage` enum; `ObservingResolver` (impls `reqwest::dns::Resolve`); worker state machine + 20s timeout; thread both fields through all snapshot construction; `push_stage` helper; `connect_stage_text` |
| `crates/client-ui/src/main.rs` | live DSL: `connecting_overlay` View + segmented-bar shader pixel fn + `connect_step_tip` Label; `App.connecting`/`connecting_prev`/`connect_stage` fields; `apply_snapshot` overlay show/hide + fade + tip refresh; `MatchEvent` duplicate-click guard |
| `crates/client-ui/Cargo.toml` | **no change** — verified: `reqwest::dns::Resolve` (`pub mod dns`) and `ClientBuilder::dns_resolver` are **not** feature-gated in 0.12.28 (available under our `rustls-tls` config); `tokio` already has `sync` for the stage channel. |

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
- **Real stages via DNS-resolver hook over fake time-cycling labels:** the user
  asked for a step-tip that reflects *which* stage the connection is at. reqwest
  exposes a custom-DNS hook (`ClientBuilder::dns_resolver`) that fires at the
  start of the connection pipeline — we set `Connecting` there. This makes the
  stages honest without rewriting the connection stack. TCP and TLS remain
  bundled inside reqwest's `HttpConnector` (not separately observable without a
  custom hyper connector) — accepted as a single "opening connection" stage.
- **20s timeout:** prevents a stuck-open overlay if `fetch_sessions` never
  resolves (e.g. dropped packets with no RST). Tunable; chosen as a generous
  upper bound for a LAN/localhost operator link.
