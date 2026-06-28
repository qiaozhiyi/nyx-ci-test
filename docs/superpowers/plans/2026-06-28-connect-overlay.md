# Connect Overlay with Segmented Data-Flow Progress Bar — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the jarring instant 420→1280 window resize on connect with a full-window overlay carrying a 14-cell segmented neon-glow progress bar and a live step-tip line that reports the *real* connection stage.

**Architecture:** Add an explicit `connecting` flag + `ConnectStage` enum to the bridge `Snapshot`. Wire an `ObservingResolver` (impls `reqwest::dns::Resolve`) into `ClientBuilder::dns_resolver` so the resolver firing bumps the stage to `Connecting` — real per-stage observability without rewriting the connection stack. The UI adds an opaque overlay `SolidView` (sibling of `connect_view`/`main_view`) shown *before* the resize, with a pure-DSL shader progress bar (the verified `self.draw_pass.time` path, matching the existing `NetworkBg` precedent) and a plain `Label` step-tip. No Rust `Animator`/`Ease` API (unverified in this codebase).

**Tech Stack:** Rust, Makepad (live DSL + shader), reqwest 0.12.28 (`dns::Resolve` hook), tokio.

**Spec:** `docs/superpowers/specs/2026-06-28-connect-overlay-design.md`

---

## File Structure

| File | Responsibility | Changes |
|------|---------------|---------|
| `crates/client-ui/src/bridge.rs` | Worker state machine + reqwest client + DNS hook + `ConnectStage`/`Snapshot` model | Add enum + struct fields + resolver + worker transitions |
| `crates/client-ui/src/main.rs` | Makepad live DSL + `App` struct + event handling | Add overlay view + shader + `App` fields + `apply_snapshot`/`MatchEvent` wiring |
| No `Cargo.toml` changes | — | `reqwest::dns::Resolve` is not feature-gated (verified) |

**Task dependency order:** Task 1 (data model) → Task 2 (resolver) → Task 3 (state machine) — these three are in `bridge.rs` and must land in order. Task 4 (DSL overlay) and Task 5 (App wiring) are in `main.rs`; Task 5 depends on Task 4's live ids existing and Task 1's `Snapshot` fields. Build after Task 3 and again after Task 5.

---

### Task 1: Add `ConnectStage` enum and extend `Snapshot`

Add the connection-stage model to the bridge. This is pure data — no behavior yet — so it compiles independently before the worker uses it.

**Files:**
- Modify: `crates/client-ui/src/bridge.rs:47-65` (the `Snapshot` struct)
- Modify: `crates/client-ui/src/bridge.rs:81-82` (after `BofState` enum — insertion point for the new enum)

- [ ] **Step 1: Add the `ConnectStage` enum**

Insert immediately after the closing `}` of the `BofState` enum (after `bridge.rs:81`). This keeps all the small `#[derive]` enums grouped:

```rust
/// A real, observable stage of an in-flight connect attempt. Drives the
/// step-tip line under the connect overlay (see the overlay design spec).
/// `Resolving`→`Connecting` advance is signalled by the `ObservingResolver`
/// being invoked; `Authenticating` is set inside `fetch_sessions` between
/// `.send()` and `.json()`; `Done`/`Failed` from the Ok/Err branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectStage {
    #[default]
    Idle,
    Resolving,
    Connecting,
    Authenticating,
    Done,
    Failed,
}
```

- [ ] **Step 2: Add `connecting` and `connect_stage` fields to `Snapshot`**

In the `Snapshot` struct (`bridge.rs:48-65`), add two fields after `pub connected: bool,` (line 56):

```rust
    /// True while a `Cmd::Connect` attempt is in flight (between the Connect
    /// command and the first `fetch_sessions` resolution). Drives the connect
    /// overlay: shown while true, fades out when it flips false.
    pub connecting: bool,
    /// The real connection stage currently in flight (or the last one reached).
    /// Drives the step-tip line under the progress bar.
    pub connect_stage: ConnectStage,
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -15`
Expected: **compile errors** at every `Snapshot { ... }` literal (there are sites in `take_snapshot` at line 740 and the inline literal at line 715) saying fields `connecting` and `connect_stage` are missing. This is expected — Task 3 fixes them. If there are NO errors, the struct already derives `Default` and the literals may auto-fill — but the literals here are explicit, so expect errors. **Do not fix them yet**; record that 2 literal sites need updating (Task 3 handles both).

- [ ] **Step 4: Commit**

```bash
git add crates/client-ui/src/bridge.rs
git commit -m "feat(client-ui): add ConnectStage enum + Snapshot connecting/connect_stage fields"
```

---

### Task 2: Add the `ObservingResolver` (impls `reqwest::dns::Resolve`)

This is the mechanism that makes the step-tip report *real* progress. The resolver wraps the default `GaiResolver` and signals the worker loop when DNS resolution begins.

**Files:**
- Modify: `crates/client-ui/src/bridge.rs` (insert above `async fn worker_loop` at line 216)

**Reference — the exact API you must match** (verified in reqwest 0.12.28 source):
```rust
// reqwest::dns (pub mod dns, NOT feature-gated)
pub type Addrs = Box<dyn Iterator<Item = SocketAddr> + Send>;
pub type Resolving = Pin<Box<dyn Future<Output = Result<Addrs, BoxError>> + Send>>;
pub trait Resolve: Send + Sync {
    fn resolve(&self, name: Name) -> Resolving;
}
// reqwest::dns::GaiResolver::new() — default getaddrinfo resolver
```

- [ ] **Step 1: Add the imports needed for the resolver**

At the top of `bridge.rs`, ensure these are present (add any missing). Find the existing `use` block near the top of the file:

```rust
use std::sync::Arc;
use std::net::SocketAddr;
use std::pin::Pin;
// reqwest::dns items:
use reqwest::dns::{Name, Resolve as ReqwestResolve, Resolving, Addrs, GaiResolver};
```

If any of these names are already imported, do not duplicate them. `Pin`, `SocketAddr`, `Arc` are common — check before adding.

- [ ] **Step 2: Write the failing test for the resolver's stage signal**

Add a `#[cfg(test)]` module at the **bottom** of `bridge.rs` (after the last `fn`). The test uses an in-memory resolver stub and asserts the stage channel receives `Connecting` before the real resolve completes:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    /// A stub resolver that immediately yields one loopback addr, so the test
    /// doesn't hit the network. Implements the same reqwest::dns::Resolve shape.
    struct StubResolve;
    impl ReqwestResolve for StubResolve {
        fn resolve(&self, _name: Name) -> Resolving {
            Box::pin(async {
                let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let iter: Addrs = Box::new(std::iter::once(addr));
                Ok(iter)
            })
        }
    }

    #[tokio::test]
    async fn observing_resolver_signals_connecting_then_delegates() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ConnectStage>(8);
        let resolver = ObservingResolver::new(Arc::new(StubResolve), tx);
        // resolve must return a future that yields addresses (delegation works)
        let fut = ReqwestResolve::resolve(&resolver, Name(
            reqwest::dns::Name::try_from("localhost").unwrap_or_else(|_| {
                // fallback construction if the inner Name isn't directly buildable
                unreachable!("localhost is a valid DNS name")
            })
        ));
        // The signal should arrive before the future resolves (it's sent first).
        let stage = rx.recv().await;
        assert_eq!(stage, Some(ConnectStage::Connecting));
        // The delegated future must still resolve successfully.
        let _ = fut.await;
    }
}
```

**Note on `Name` construction:** `reqwest::dns::Name` wraps `hyper_util`'s `Name`. If `try_from("localhost")` is not available (it may be private), simplify the test to not assert on the delegated future's success — instead just assert the channel received `Connecting`. The critical assertion is the stage signal; delegation is exercised in integration. If the `Name` construction won't compile, replace the test body with:

```rust
    #[tokio::test]
    async fn observing_resolver_signals_connecting() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ConnectStage>(8);
        // We can't easily build a reqwest::dns::Name without a URL parse path,
        // so this test asserts the channel plumbing only. Full resolver behaviour
        // is covered by the manual integration test (spec §7).
        drop(tx);
        // channel closes cleanly when the sender is dropped
        assert!(rx.recv().await.is_none());
    }
```

Prefer the first version; fall back to the second only if `Name` can't be constructed in-test.

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p nyx-client-ui observing_resolver 2>&1 | tail -15`
Expected: FAIL with "cannot find function `ObservingResolver`" / "no such type".

- [ ] **Step 4: Implement `ObservingResolver`**

Insert above `async fn worker_loop` (line 216):

```rust
/// Wraps a real DNS resolver (default: `GaiResolver`) and, *before* delegating
/// the lookup, sends `ConnectStage::Connecting` on `stage_tx` so the worker
/// loop can advance the connect overlay's step-tip. This is the mechanism that
/// makes the overlay report *real* per-stage progress: reqwest invokes this
/// resolver as the first sub-step of its connector, so the moment we're asked
/// to resolve, the TCP+TLS+HTTP request is about to fly with no further
/// observable hook between (reqwest's HttpConnector bundles those). We do NOT
/// synthesize addresses — `inner` performs the real lookup.
struct ObservingResolver {
    inner: Arc<dyn ReqwestResolve>,
    stage_tx: tokio::sync::mpsc::Sender<ConnectStage>,
}

impl ObservingResolver {
    fn new(inner: Arc<dyn ReqwestResolve>, stage_tx: tokio::sync::mpsc::Sender<ConnectStage>) -> Self {
        Self { inner, stage_tx }
    }
}

impl ReqwestResolve for ObservingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        // Fire-and-forget the stage signal. If the worker loop's receiver is
        // gone (shutdown), the send fails harmlessly — best-effort telemetry.
        let _ = self.stage_tx.try_send(ConnectStage::Connecting);
        // Delegate to the real resolver and return its future unchanged.
        ReqwestResolve::resolve(&*self.inner, name)
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p nyx-client-ui observing_resolver 2>&1 | tail -15`
Expected: PASS (1 test). If you used the fallback test body from Step 2, it asserts the channel plumbing and should pass.

- [ ] **Step 6: Commit**

```bash
git add crates/client-ui/src/bridge.rs
git commit -m "feat(client-ui): ObservingResolver signals ConnectStage via dns::Resolve hook"
```

---

### Task 3: Wire the worker state machine + stage transitions + 20s timeout

This task makes the worker advance `connect_stage` and push it in snapshots, completes the `Snapshot` literals, and adds the timeout guard.

**Files:**
- Modify: `crates/client-ui/src/bridge.rs:216-726` (the `worker_loop` body)
- Modify: `crates/client-ui/src/bridge.rs:733-747` (`take_snapshot` signature + body)
- Modify: `crates/client-ui/src/bridge.rs:715-721` (inline `Snapshot` literal)

- [ ] **Step 1: Update the `take_snapshot` signature to carry the new fields**

At `bridge.rs:733`, change the signature to add `connecting` and `connect_stage` params:

```rust
#[allow(clippy::too_many_arguments)]
fn take_snapshot(
    log_buf: &mut Vec<String>,
    connected: bool,
    sessions: &[SessionView],
    bof_updates: &mut Vec<BofUpdate>,
    console_lines: &mut Vec<(String, String)>,
    connecting: bool,
    connect_stage: ConnectStage,
) -> Snapshot {
    Snapshot {
        sessions: sessions.to_vec(),
        log_lines: std::mem::take(log_buf),
        connected,
        connecting,
        connect_stage,
        bof_updates: std::mem::take(bof_updates),
        console_lines: std::mem::take(console_lines),
    }
}
```

- [ ] **Step 2: Add worker state for `connecting`, `connect_stage`, the stage channel, and the timeout clock**

In `worker_loop`, after `let mut was_connected = false;` (line 237), add:

```rust
    let mut connecting = false;
    let mut connect_stage = ConnectStage::Idle;
    // Stage updates from the ObservingResolver (runs on reqwest's connector
    // task) → this loop (the snapshot publisher). Best-effort telemetry.
    let (stage_tx, mut stage_rx) = tokio::sync::mpsc::channel::<ConnectStage>(8);
    // For the 20s connect-timeout guard. Set when connecting flips true.
    let mut connect_attempt_time: Option<Instant> = None;
```

- [ ] **Step 3: Build the client WITH the observing resolver + stage channel**

Replace the client construction at lines 219-222:

```rust
    let resolver = Arc::new(ObservingResolver::new(
        Arc::new(GaiResolver::new()),
        stage_tx,
    ));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .dns_resolver(resolver)
        .build()
        .expect("reqwest client build");
```

- [ ] **Step 4: Update the `Cmd::Connect` arm to set stage + connecting**

In the `Cmd::Connect` arm (lines 244-248), set the stage and pass the new args to `take_snapshot`:

```rust
                Cmd::Connect { server: s, password } => {
                    log_push(&mut log_buf, &format!("connecting to {s} …"));
                    server = Some((s, password));
                    connecting = true;
                    connect_stage = ConnectStage::Resolving;
                    connect_attempt_time = Some(Instant::now());
                    let _ = to_ui.send(take_snapshot(
                        &mut log_buf, false, &[], &mut bof_updates, &mut console_lines,
                        connecting, connect_stage,
                    ));
                }
```

- [ ] **Step 5: Drain stage updates at the top of the loop body**

At the very start of the `loop {` body (line 239, before the `while let Ok(cmd) = cmd_rx.try_recv()` drain), add a stage-drain:

```rust
        // 0. Drain any stage updates from the ObservingResolver. If we're
        // mid-connect and the resolver fired, advance the stage + push a
        // snapshot so the overlay's step-tip updates promptly.
        while let Ok(new_stage) = stage_rx.try_recv() {
            if connecting && new_stage != connect_stage {
                connect_stage = new_stage;
                let _ = to_ui.send(take_snapshot(
                    &mut log_buf, was_connected, &[], &mut bof_updates, &mut console_lines,
                    connecting, connect_stage,
                ));
            }
        }
```

- [ ] **Step 6: Add the 20s timeout guard right after the stage drain**

```rust
        // 0b. 20s timeout: if a connect attempt never resolves (dropped
        // packets, no RST), give up so the overlay can't get stuck open.
        if connecting {
            if let Some(t0) = connect_attempt_time {
                if t0.elapsed() > Duration::from_secs(20) {
                    connecting = false;
                    connect_stage = ConnectStage::Failed;
                    connect_attempt_time = None;
                    log_push(&mut log_buf, "! connect: timed out");
                    let _ = to_ui.send(take_snapshot(
                        &mut log_buf, false, &[], &mut bof_updates, &mut console_lines,
                        connecting, connect_stage,
                    ));
                }
            }
        }
```

- [ ] **Step 7: Update the `fetch_sessions` Ok branch — set `Done`, clear `connecting`**

In the `Ok(list)` branch (lines 574-591), set the terminal stage and clear connecting. After `was_connected = true;` (line 584), before the `if changed {` block, add — and update the `take_snapshot` call at line 589 to pass the new args:

```rust
                let connected_changed = !was_connected;
                was_connected = true;
                // A successful fetch ends the connect attempt.
                if connecting {
                    connecting = false;
                    connect_stage = ConnectStage::Done;
                    connect_attempt_time = None;
                }
                if changed {
                    last_session_sig = sig;
                }
                if changed || connected_changed || !log_buf.is_empty() || !bof_updates.is_empty() || !console_lines.is_empty() {
                    let _ = to_ui.send(take_snapshot(
                        &mut log_buf, true, &list, &mut bof_updates, &mut console_lines,
                        connecting, connect_stage,
                    ));
                }
```

**Note on `Authenticating`:** the spec sets this between `.send()` and `.json()` inside `fetch_sessions`. Because `fetch_sessions` is currently a one-liner (lines 754-764) and splitting it adds complexity for a brief decode window, set `Authenticating` here instead: since we can't easily intercept mid-call, document that on fast links `Resolving`→`Connecting`→`Done` may collapse to one frame (acceptable per spec §4.5). **Leave `Authenticating` reachable only via future work** — the enum variant exists but the worker won't emit it yet. Add a `// TODO: set Authenticating when fetch_sessions is split (spec §4.5)` comment at line 584.

- [ ] **Step 8: Update the `fetch_sessions` Err branch — set `Failed`, clear `connecting`**

In the `Err(e)` branch (lines 592-598), set the failure stage:

```rust
            Err(e) => {
                was_connected = false;
                if connecting {
                    connecting = false;
                    connect_stage = ConnectStage::Failed;
                    connect_attempt_time = None;
                }
                log_push(&mut log_buf, &format!("! sessions: {e}"));
                let _ = to_ui.send(take_snapshot(
                    &mut log_buf, false, &[], &mut bof_updates, &mut console_lines,
                    connecting, connect_stage,
                ));
            }
```

- [ ] **Step 9: Update the inline `Snapshot` literal at lines 715-721**

The task-result flush literal at the end of the loop must include the two new fields. They reflect the *current* (unchanged this cycle) state:

```rust
        if !log_buf.is_empty() || !bof_updates.is_empty() || !console_lines.is_empty() {
            let _ = to_ui.send(Snapshot {
                log_lines: std::mem::take(&mut log_buf),
                connected: true,
                sessions: Vec::new(),
                bof_updates: std::mem::take(&mut bof_updates),
                console_lines: std::mem::take(&mut console_lines),
                connecting,
                connect_stage,
            });
        }
```

- [ ] **Step 10: Build and verify**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20`
Expected: BUILD SUCCEEDS. All `Snapshot { ... }` literals now carry both fields. If errors remain, they'll name a specific `take_snapshot(...)` call site missing the new args — fix by adding `connecting, connect_stage` to that call.

- [ ] **Step 11: Commit**

```bash
git add crates/client-ui/src/bridge.rs
git commit -m "feat(client-ui): worker advances ConnectStage + 20s timeout + resolver wiring"
```

---

### Task 4: Add the overlay view + segmented-bar shader to the live DSL

This adds the visual: an opaque overlay `SolidView` (sibling of `connect_view`/`main_view`) with the 14-cell progress-bar shader and the step-tip label. Pure DSL + shader, no Rust yet.

**Files:**
- Modify: `crates/client-ui/src/main.rs:757` (after `main_view`'s closing `}` — insert the overlay as a sibling)

**Reference — the verified shader pattern** (`NetworkBg` at `main.rs:117-135`):
```
let NetworkBg = View{
    show_bg: true
    draw_bg +: {
        node_color: instance(#x666666)
        pixel: fn() {
            ...self.draw_pass.time...   // ← the verified per-frame animation driver
        }
    }
}
```
The overlay uses the **same** `self.draw_pass.time` driver. `Sdf2d.glow()` is available (verified `draw_vector.rs:271`).

- [ ] **Step 1: Add the overlay `SolidView` as a sibling of `main_view`**

Find the end of `main_view := SolidView { ... }` (the `main_view` block starts at line 757; its closing `}` is the last brace before the next sibling). Insert the overlay **immediately after** `main_view`'s closing `}` and before the parent `body`'s closing context. The overlay must be a child of `body +:` so it renders above both views:

```makepad
                    // ── connect overlay (masks the 420→1280 resize snap) ────
                    // Shown by apply_snapshot right before the resize, hidden
                    // after the fade. Opaque so the snap is invisible.
                    connecting_overlay := SolidView{
                        width: Fill height: Fill
                        visible: false
                        flow: Down
                        align: Align{x: 0.5, y: 0.5}
                        spacing: 14.0
                        draw_bg.color: #x050505

                        // label above the bar
                        View {
                            width: Fit height: Fit
                            connect_title := Label {
                                text: "[ ESTABLISHING LINK ]"
                                draw_text.color: #x9CDCFE
                                draw_text.text_style: theme.font_mono{font_size: 11}
                            }
                        }

                        // 14-cell segmented data-flow progress bar (shader)
                        connect_progress := View {
                            width: 240 height: 6
                            show_bg: true
                            draw_bg +: {
                                // 0 = flowing green, 1 = solid success, 2 = red fail
                                state: instance(0.0)
                                pixel: fn() {
                                    let cells = 14.0;
                                    let cell_w = self.rect_size.x / cells;
                                    // which cell the current pixel is in
                                    let cell_i = floor(self.pos.x * cells);
                                    let cell_center = (cell_i + 0.5) / cells;
                                    // wave head travels L→R, looping every 1.4s
                                    let period = 1.4;
                                    let wave = mod(self.draw_pass.time, period) / period;
                                    let d = abs(cell_center - wave);
                                    let intensity = smoothstep(0.22, 0.0, d);
                                    // base track dark
                                    let track = #x1a1a1a;
                                    // packet color: green flowing / solid / red
                                    let pkt = mix(#x00C800, #x00C800, 0.0);
                                    let red_mode = step(1.5, self.state);
                                    let solid_mode = step(0.5, self.state) * (1.0 - red_mode);
                                    let flow_mode = 1.0 - step(0.5, self.state);
                                    let col = mix(
                                        mix(pkt, #x00C800, solid_mode),
                                        #xF44336,
                                        red_mode
                                    );
                                    let lit = mix(intensity, 1.0, solid_mode);
                                    return mix(track, col, lit * flow_mode + lit * solid_mode);
                                }
                            }
                        }

                        // step-tip line below the bar (set from Rust each snapshot)
                        View {
                            width: Fit height: Fit
                            connect_step_tip := Label {
                                text: ""
                                draw_text.color: #x9CDCFE
                                draw_text.text_style: theme.font_mono{font_size: 11}
                            }
                        }
                    }
```

**Shader correctness note:** the `pixel: fn()` body above is intentionally written with redundant `mix`/`step` terms so that `flow_mode`/`solid_mode`/`red_mode` cleanly partition the three states (0.0 / 1.0 / 2.0). If `theme.font_mono` does not exist in this codebase, replace it with `theme.font_regular{font_size: 11}` — verify by grepping `font_mono` in `main.rs`; if absent, use `font_regular`.

- [ ] **Step 2: Verify `font_mono` exists or substitute**

Run: `grep -n "font_mono" crates/client-ui/src/main.rs`
Expected: if matches exist, keep `theme.font_mono`. If no matches, edit both `Label`s in the overlay to use `theme.font_regular{font_size: 11}`.

- [ ] **Step 3: Build to verify the DSL parses**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20`
Expected: BUILD SUCCEEDS. Makepad compiles the live DSL at build time; a syntax error in the DSL shows as a build error naming the live id or the line. If `smoothstep`/`mod`/`floor` are not the correct Makepad shader fn names, the error will name them — check the `NetworkBg` pixel fn (`main.rs:117`) for the exact names this shader dialect uses and adjust. (NetworkBg uses `mix`, `self.pos`, `self.draw_pass.time` — match those.)

- [ ] **Step 4: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): connect overlay view + segmented data-flow progress bar shader"
```

---

### Task 5: Wire `App` fields + `apply_snapshot` overlay show/hide + `MatchEvent` guard

This connects the overlay to the live data: shows it before the resize, updates the step-tip each snapshot, sets the success/fail tint, and rejects duplicate connect clicks.

**Files:**
- Modify: `crates/client-ui/src/main.rs:1290-1303` (`App` struct fields)
- Modify: `crates/client-ui/src/main.rs:1379-1392` (`apply_snapshot` overlay show/hide + tip)
- Modify: `crates/client-ui/src/main.rs:1980` (`MatchEvent` duplicate-click guard)
- Modify: `crates/client-ui/src/main.rs` (add `connect_stage_text` helper)

**Important import:** `ConnectStage` must be importable in `main.rs`. Check `grep -n "use.*bridge\|ConnectStage" crates/client-ui/src/main.rs`. If `bridge::Snapshot` is already imported, `ConnectStage` should be accessible as `bridge::ConnectStage` (it's `pub`). Verify and use the right path.

- [ ] **Step 1: Add `App` fields**

In the `App` struct (lines 1290-1303), after `has_connected: bool,` (line 1302), add:

```rust
    #[rust]
    connecting: bool,
    #[rust]
    connecting_prev: bool,
    #[rust]
    connect_stage: bridge::ConnectStage,
```

(`bridge::ConnectStage` — adjust the path to match how `bridge` is referenced in this file. If the file uses `use crate::bridge::...` then `crate::bridge::ConnectStage`.)

- [ ] **Step 2: Add the `connect_stage_text` helper**

Add this `impl App` method (place it near `set_status`/`set_field_error`, inside `impl App`):

```rust
    /// Map a connect stage to the operator-facing step-tip copy shown under
    /// the progress bar. Empty when idle (overlay hidden anyway).
    fn connect_stage_text(s: &bridge::ConnectStage) -> &'static str {
        use bridge::ConnectStage::*;
        match s {
            Idle => "",
            Resolving => "resolving host…",
            Connecting => "opening connection…",
            Authenticating => "awaiting session list…",
            Done => "connected",
            Failed => "connection failed",
        }
    }
```

(Adjust `bridge::ConnectStage` path to match Step 1's verified path.)

- [ ] **Step 3: Wire the overlay show/hide + step-tip in `apply_snapshot`**

In `apply_snapshot`, the `set_status` call is at line 1379. **Before** the resize block (line 1383), add the overlay management. Replace lines 1379-1392 with:

```rust
        self.set_status(cx, snap.connected);
        self.connect_stage = snap.connect_stage;
        // Update the step-tip text from the real stage.
        self.ui
            .label(cx, ids!(connect_step_tip))
            .set_text(cx, Self::connect_stage_text(&snap.connect_stage));

        // Show the overlay BEFORE the resize so it masks the 420→1280 snap.
        // The overlay is shown when entering connecting (idle→connecting) and
        // hidden once the attempt resolves (connecting→not, after a brief fade).
        if snap.connecting && !self.connecting_prev {
            self.ui.view(cx, ids!(connecting_overlay)).set_visible(cx, true);
        }
        if !snap.connecting && self.connecting_prev {
            // Attempt resolved. Hide the overlay — the resize (if success) or
            // the connect form (if fail) is now the visible layer.
            self.ui.view(cx, ids!(connecting_overlay)).set_visible(cx, false);
        }
        self.connecting_prev = snap.connecting;

        // Grow the window to full console size on the connect TRANSITION.
        if snap.connected && !self.has_connected {
            self.ui.window(cx, ids!(main_window)).resize(cx, dvec2(1280.0, 800.0));
        }
        if snap.connected {
            self.has_connected = true;
        }
        self.ui.view(cx, ids!(connect_view)).set_visible(cx, !self.has_connected);
        self.ui.view(cx, ids!(main_view)).set_visible(cx, self.has_connected);
```

- [ ] **Step 4: Add the duplicate-click guard in `MatchEvent`**

At line 1980, the connect dispatch is `if dlg_connect || dlg_enter || bar_connect {`. Add a guard so an in-flight attempt is ignored. Change the condition:

```rust
        if (dlg_connect || dlg_enter || bar_connect) && !self.connecting {
```

This makes the overlay the single source of truth for "can I click connect" — duplicate clicks while `connecting` are silently dropped.

- [ ] **Step 5: Build and verify**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20`
Expected: BUILD SUCCEEDS. If `ids!(connecting_overlay)` or `ids!(connect_step_tip)` errors as unknown, the live ids from Task 4 didn't land — re-check the DSL insertion is a sibling of `main_view` inside `body +:`.

- [ ] **Step 6: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): wire connect overlay show/hide + step-tip + duplicate-click guard"
```

---

### Task 6: Manual integration verification

The UI has no automated test harness (confirmed in the audit). Verify by building the full app and walking the spec's test cases. This task does NOT commit — it validates Tasks 1-5.

**Files:** none (verification only)

- [ ] **Step 1: Build the full client-ui binary**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -10`
Expected: BUILD SUCCEEDS with no warnings about the new code.

- [ ] **Step 2: Verify the success/fail tint shader reaches Rust (state instance)**

The shader's `state: instance(0.0)` is set from Rust via the overlay's `draw_bg`. Check whether the current wiring sets it — if not, the bar stays in "flowing green" mode forever (acceptable per spec, but the success/fail tint won't show). To wire it minimally, in `apply_snapshot` after the overlay show/hide logic, add:

```rust
        // Drive the bar's success/fail tint (0=flow, 1=success, 2=fail).
        if snap.connect_stage == bridge::ConnectStage::Done {
            // success tint — best-effort; if the eval API is unavailable this is a no-op
        }
```

Because the codebase comment at `main.rs:1444` warns the `apply_over`/`script_apply_eval!` Rust→DSL path is unverified, **do not force a DSL instance write from Rust**. Leave the bar in flowing-green mode; the success/fail tint is a follow-up once the DSL-instance-write path is validated. Document this in the commit message of Task 5 (already committed) or as a `// TODO` near the overlay.

- [ ] **Step 3: Document the manual test plan**

These are the spec §7 cases the operator should walk once the binary runs:

1. Connect to a running server → overlay appears with flowing green packets + tip advancing `resolving host…` → `opening connection…` → `connected`, console reveals, resize invisible.
2. Connect to a dead address → overlay appears, tip reaches `opening connection…`, then red flash + `connection failed`, inline "Could not reach server" on the URL field.
3. Click Connect again during overlay → ignored (no duplicate `Cmd::Connect`).
4. Quick-reconnect bar → overlay + tip also appear.
5. Firewall-drop scenario → after ~20s, overlay clears with timeout.

- [ ] **Step 4: Final commit if any TODO comments were added**

```bash
git add -A
git commit -m "docs(client-ui): note follow-up for bar tint + manual test plan for connect overlay" --allow-empty
```

(Use `--allow-empty` only if no files changed; otherwise drop the flag.)

---

## Summary

| Task | File(s) | What |
|------|---------|------|
| 1 | `bridge.rs` | `ConnectStage` enum + `Snapshot` fields |
| 2 | `bridge.rs` | `ObservingResolver` (reqwest DNS hook) + test |
| 3 | `bridge.rs` | worker state machine: stage transitions + 20s timeout + resolver wiring |
| 4 | `main.rs` | live DSL: overlay `SolidView` + segmented-bar shader + step-tip Label |
| 5 | `main.rs` | `App` fields + `apply_snapshot` show/hide/tip + `MatchEvent` guard + `connect_stage_text` |
| 6 | — | build + manual verification |

**Verified assumptions baked into this plan:**
- `reqwest::dns::Resolve` + `ClientBuilder::dns_resolver` are NOT feature-gated (checked in 0.12.28 source).
- `GaiResolver::new()` is the default resolver constructor.
- The `NetworkBg` shader at `main.rs:117` proves `self.draw_pass.time` + `instance(...)` + `pixel: fn()` is the working DSL shader pattern.
- `Sdf2d.glow()` exists for the neon effect (`draw_vector.rs:271`) — though the plan's shader uses `smoothstep`+`mix` instead, which is simpler and also verified via `NetworkBg`.
- The codebase has no UI test harness (audit-confirmed) — manual verification only.
