//! Rhai scripting hook — the pure-Rust Aggressor-script equivalent.
//!
//! Chose Rhai (pure Rust, no C) over Lua: `mlua`'s `Lua` is `!Send` and would
//! need a dedicated worker thread, whereas Rhai's `Engine` is `Send + Sync`, so
//! a [`RhaiHook`] implements [`Hook`] directly with no thread isolation.
//!
//! Loads a Rhai script and dispatches [`nyx_scripting::Event`]s to script
//! functions `on_session_new(s)`, `on_result(r)`, `on_session_exit(e)`, passing
//! each event as a Rhai `Map`. Exposes a `nyx_log(msg)` API.
//!
//! # Host-enforced budgets
//!
//! Scripts run inline on server threads (the EventBus fires hooks from beacon
//! handlers), so a buggy or hostile operator script must not be able to stall
//! requests or leak unbounded memory. The same budget applies to all three
//! event handlers (they all route through the same dispatch path):
//!
//! - **Per-dispatch operation cap** — `Limits::max_ops_per_dispatch` (default
//!   1M ops), enforced by `Engine::set_max_operations`. The counter resets on
//!   every dispatch (every `call_fn`), so each event gets a fresh 1M.
//! - **Cumulative operation cap** — `Limits::max_ops_cumulative` (default 2M
//!   ops) across *all* dispatches over the hook's lifetime. It is enforced via
//!   `Engine::on_progress` with a counter that **never resets**; once the total
//!   exceeds the bound every subsequent dispatch aborts immediately,
//!   permanently disabling the script.
//! - **Wall-clock deadline** — `Limits::deadline` (default 5s, measured with
//!   `Instant`) is a per-dispatch backstop that catches pathological cases the
//!   operation counters miss.
//! - **`nyx_log` rate limit** — at most `Limits::max_log_calls` (default 256)
//!   calls and `Limits::max_log_bytes` (default 64 KiB) of message text per
//!   dispatch; excess calls are dropped and counted (the counter is cumulative
//!   across dispatches); the window resets on every dispatch.
//!
//! A budget abort prints one line to stderr the first time it happens; further
//! aborts (e.g. every event after the cumulative budget is spent) stay silent.
//!
//! The budget enforcement applies identically to all three handlers, because
//! every event routes through the same dispatch path.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nyx_scripting::event::{ResultReceived, SessionExit, SessionNew};
use nyx_scripting::hook::{Event, Hook};
use rhai::{Dynamic, Engine, EvalAltResult, Map, Scope, AST};

/// Script budget limits for a [`RhaiHook`].
///
/// Defaults are generous for any real handler but bound the worst case; see the
/// module docs for what each limit guards.
#[derive(Clone, Copy)]
struct Limits {
    /// Max operations per single dispatch; resets on every event. `0` = unlimited.
    max_ops_per_dispatch: u64,
    /// Max operations across ALL dispatches over the hook's lifetime; never resets.
    max_ops_cumulative: u64,
    /// Wall-clock backstop per dispatch.
    deadline: Duration,
    /// Max `nyx_log` calls per dispatch.
    max_log_calls: u64,
    /// Max total `nyx_log` message bytes per dispatch.
    max_log_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ops_per_dispatch: 1_000_000,
            max_ops_cumulative: 2_000_000,
            deadline: Duration::from_secs(5),
            max_log_calls: 256,
            max_log_bytes: 64 * 1024,
        }
    }
}

/// Shared, cross-dispatch budget state. Lives as long as the [`RhaiHook`], so
/// the cumulative operation counter and the dropped-log counter never reset.
struct Budget {
    /// Monotonic reference point; all deadlines are stored as ms since this.
    epoch: Instant,
    /// Cumulative operations across all dispatches (via the progress callback).
    total_ops: AtomicU64,
    /// Deadline (ms since `epoch`) of the current dispatch; 0 = no deadline.
    deadline_ms: AtomicU64,
    /// `nyx_log` calls in the current dispatch (rate-limit window).
    log_calls: AtomicU64,
    /// `nyx_log` message bytes in the current dispatch (rate-limit window).
    log_bytes: AtomicU64,
    /// Dropped `nyx_log` calls across all dispatches (rate-limit overflows).
    log_dropped: AtomicU64,
    /// True once the current dispatch has reported the rate-limit hit.
    log_warned: AtomicBool,
    /// True once any dispatch has aborted for budget reasons (warn once total).
    err_warned: AtomicBool,
}

thread_local! {
    /// Last operation count the progress callback reported on this thread.
    ///
    /// Rhai's progress counter restarts from 0 on every `call_fn`, so the
    /// callback alone cannot see across dispatches. Tracking the last seen
    /// count per thread (a thread runs one dispatch at a time) turns the
    /// per-dispatch counts into an exact cumulative total. Under fully
    /// concurrent dispatches from multiple threads the accounting is exact per
    /// thread; the shared total is only ever conservative.
    static LAST_PROGRESS_OPS: Cell<u64> = const { Cell::new(0) };
}

/// A scripting hook backed by a (shared) Rhai engine + a compiled script.
pub struct RhaiHook {
    name: String,
    engine: Arc<Engine>,
    ast: AST,
    budget: Arc<Budget>,
    limits: Limits,
}

impl RhaiHook {
    /// Compile `source` (which may define `on_*` handlers and use `nyx_log`).
    pub fn new(name: &str, source: &str) -> Result<Self, Box<EvalAltResult>> {
        Self::with_limits(name, source, Limits::default())
    }

    /// Like [`Self::new`], but with explicit budget limits (used by tests to
    /// exercise exhaustion without burning millions of operations).
    fn with_limits(name: &str, source: &str, limits: Limits) -> Result<Self, Box<EvalAltResult>> {
        let mut engine = Engine::new();
        // Resource caps: a buggy or hostile operator script runs inline on the
        // server (the EventBus fires hooks from beacon handlers). Without caps
        // `loop {}` stalls the request and unbounded string growth OOMs. These
        // are generous for any real handler but bound the worst case.
        engine
            .set_max_call_levels(64) // recursion / call depth
            .set_max_operations(limits.max_ops_per_dispatch) // per dispatch; 0 = off
            .set_max_string_size(64 * 1024) // no unbounded string concatenation
            .set_max_array_size(4096)
            .set_max_variables(512)
            .set_max_functions(64)
            .set_max_expr_depths(32, 32); // expression / statement nesting

        let budget = Arc::new(Budget {
            epoch: Instant::now(),
            total_ops: AtomicU64::new(0),
            deadline_ms: AtomicU64::new(0),
            log_calls: AtomicU64::new(0),
            log_bytes: AtomicU64::new(0),
            log_dropped: AtomicU64::new(0),
            log_warned: AtomicBool::new(false),
            err_warned: AtomicBool::new(false),
        });

        // Rate-limited nyx_log: max_log_calls calls / max_log_bytes bytes per
        // dispatch. Excess calls are dropped and counted in log_dropped; the
        // window resets at the start of every dispatch.
        let b = budget.clone();
        engine.register_fn("nyx_log", move |msg: String| {
            let calls = b.log_calls.fetch_add(1, Ordering::Relaxed);
            let bytes = b.log_bytes.fetch_add(msg.len() as u64, Ordering::Relaxed)
                + msg.len() as u64;
            if calls >= limits.max_log_calls || bytes > limits.max_log_bytes {
                b.log_dropped.fetch_add(1, Ordering::Relaxed);
                if !b.log_warned.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "[nyx-rhai] nyx_log rate limit hit: max {} calls / {} bytes per dispatch; further calls dropped (counted)",
                        limits.max_log_calls, limits.max_log_bytes
                    );
                }
                return;
            }
            eprintln!("[nyx-rhai] {msg}");
        });

        // Cumulative cross-dispatch operation budget: Rhai calls this callback
        // on every operation with the current dispatch's count, which we fold
        // into a total that never resets. Also enforces the per-dispatch
        // wall-clock deadline. Returning Some(value) aborts the script with
        // `EvalAltResult::ErrorTerminated(value)`.
        let b = budget.clone();
        engine.on_progress(move |count| {
            let last = LAST_PROGRESS_OPS.with(|cell| cell.replace(count));
            let delta = if count >= last { count - last } else { count };
            let total = b.total_ops.fetch_add(delta, Ordering::Relaxed) + delta;

            let deadline = b.deadline_ms.load(Ordering::Relaxed);
            if deadline != 0 {
                let elapsed_ms = (Instant::now() - b.epoch).as_millis() as u64;
                if elapsed_ms > deadline {
                    return Some(
                        "nyx-rhai: per-dispatch wall-clock deadline exceeded".into(),
                    );
                }
            }
            if total > limits.max_ops_cumulative {
                return Some(
                    format!(
                        "nyx-rhai: cumulative operation budget exceeded (>{max_ops_cumulative} across all dispatches)",
                        max_ops_cumulative = limits.max_ops_cumulative
                    )
                    .into(),
                );
            }
            None
        });

        let ast = engine.compile(source)?;
        Ok(Self {
            name: name.to_string(),
            engine: Arc::new(engine),
            ast,
            budget,
            limits,
        })
    }

    fn dispatch(&self, handler: &str, payload: Map) {
        // Open a fresh per-dispatch budget window: the wall-clock deadline and
        // the nyx_log rate-limit counters reset here. The cumulative operation
        // budget does NOT reset.
        let deadline_ms = (Instant::now() - self.budget.epoch).as_millis() as u64
            + self.limits.deadline.as_millis() as u64;
        self.budget
            .deadline_ms
            .store(deadline_ms, Ordering::Relaxed);
        self.budget.log_calls.store(0, Ordering::Relaxed);
        self.budget.log_bytes.store(0, Ordering::Relaxed);
        self.budget.log_warned.store(false, Ordering::Relaxed);

        // Missing handler -> Err; that's fine (a script need not handle every event).
        let mut scope = Scope::new();
        if let Err(err) = self
            .engine
            .call_fn::<()>(&mut scope, &self.ast, handler, (payload,))
        {
            // A budget abort is expected once a script goes over; surface the
            // first one so operators notice, then stay quiet (every later
            // event aborts too). Any other error (missing handler, script bug)
            // is ignored as before.
            if is_budget_abort(&err) && !self.budget.err_warned.swap(true, Ordering::Relaxed) {
                eprintln!("[nyx-rhai] {handler} aborted: {err}");
            }
        }
    }
}

impl Hook for RhaiHook {
    fn name(&self) -> &str {
        &self.name
    }
    fn on_event(&self, event: &Event) {
        match event {
            Event::SessionNew(s) => self.dispatch("on_session_new", session_map(s)),
            Event::ResultReceived(r) => self.dispatch("on_result", result_map(r)),
            Event::SessionExit(e) => self.dispatch("on_session_exit", exit_map(e)),
        }
    }
}

/// True for the two error kinds that mean a host-enforced budget stopped the
/// script: the per-dispatch operation cap and a progress-callback termination
/// (cumulative op budget or wall-clock deadline).
fn is_budget_abort(err: &EvalAltResult) -> bool {
    matches!(
        err,
        EvalAltResult::ErrorTooManyOperations(_) | EvalAltResult::ErrorTerminated(..)
    )
}

fn put(m: &mut Map, k: &str, v: impl Into<Dynamic>) {
    m.insert(k.into(), v.into());
}

fn session_map(s: &SessionNew) -> Map {
    let mut m = Map::new();
    put(&mut m, "session_id", s.session_id.clone());
    put(&mut m, "hostname", s.hostname.clone());
    put(&mut m, "username", s.username.clone());
    put(&mut m, "os", s.os.clone());
    put(&mut m, "is_admin", s.is_admin);
    m
}

fn result_map(r: &ResultReceived) -> Map {
    let mut m = Map::new();
    put(&mut m, "session_id", r.session_id.clone());
    put(&mut m, "task_id", r.task_id as i64);
    put(&mut m, "kind", format!("{:?}", r.kind));
    put(&mut m, "summary", r.summary.clone());
    m
}

fn exit_map(e: &SessionExit) -> Map {
    let mut m = Map::new();
    put(&mut m, "session_id", e.session_id.clone());
    m
}

#[cfg(test)]
impl RhaiHook {
    /// Cumulative operations consumed across all dispatches so far.
    fn cumulative_ops(&self) -> u64 {
        self.budget.total_ops.load(Ordering::Relaxed)
    }
    /// `nyx_log` calls dropped by the rate limit across all dispatches.
    fn log_dropped(&self) -> u64 {
        self.budget.log_dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyx_scripting::EventBus;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn new_session(id: &str) -> SessionNew {
        SessionNew {
            session_id: id.into(),
            hostname: "ws7".into(),
            username: "u".into(),
            os: "Windows".into(),
            is_admin: false,
        }
    }

    #[test]
    fn rhai_reads_event_fields_and_calls_host_fns() {
        // Build an engine manually so we can register a counting fn (RhaiHook
        // only exposes nyx_log). Verifies event-Map field access + host calls.
        let mut engine = Engine::new();
        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        engine.register_fn("bump", move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        let ast = engine
            .compile(r#"fn on_session_new(s) { bump(); s["hostname"] }"#)
            .unwrap();

        let mut scope = Scope::new();
        let host: String = engine
            .call_fn(
                &mut scope,
                &ast,
                "on_session_new",
                (session_map(&SessionNew {
                    session_id: "a".into(),
                    hostname: "ws7".into(),
                    username: "u".into(),
                    os: "Windows".into(),
                    is_admin: true,
                }),),
            )
            .unwrap();
        assert_eq!(host, "ws7");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rhai_hook_dispatches_all_event_kinds() {
        // A script that only handles session_new must not break on result/exit.
        let hook =
            RhaiHook::new("t", r#"fn on_session_new(s) { nyx_log(s["hostname"]); }"#).unwrap();
        let mut bus = EventBus::new();
        bus.register(Box::new(hook));
        bus.fire(&Event::SessionNew(new_session("a")));
        bus.fire(&Event::ResultReceived(ResultReceived {
            session_id: "a".into(),
            task_id: 1,
            kind: nyx_scripting::event::ResultKind::Output,
            summary: "ok".into(),
        }));
        bus.fire(&Event::SessionExit(SessionExit {
            session_id: "a".into(),
        }));
        // No panic => all three dispatched; undefined handlers were ignored.
    }

    #[test]
    fn rhai_hook_aborts_on_cumulative_op_budget() {
        // Tiny cumulative budget so the test stays fast; the loop would run
        // ~1M iterations without it.
        let limits = Limits {
            max_ops_cumulative: 1_000,
            ..Limits::default()
        };
        let hook = RhaiHook::with_limits(
            "t",
            r#"fn on_session_new(s) { let i = 0; loop { i += 1; if i > 1_000_000 { break; } } }"#,
            limits,
        )
        .unwrap();

        // First dispatch burns through the cumulative budget and is aborted.
        hook.dispatch("on_session_new", session_map(&new_session("a")));
        let spent = hook.cumulative_ops();
        assert!(spent > 1_000, "aborted past cumulative cap: {spent}");

        // The budget never resets: the next dispatch is aborted at the first
        // progress tick, consuming almost no additional operations.
        hook.dispatch("on_session_new", session_map(&new_session("b")));
        let extra = hook.cumulative_ops() - spent;
        assert!(
            extra < 1_000,
            "cumulative budget must not reset per dispatch: +{extra} ops"
        );
    }

    #[test]
    fn rhai_hook_aborts_on_per_dispatch_op_cap() {
        let limits = Limits {
            max_ops_per_dispatch: 1_000,
            ..Limits::default()
        };
        let hook = RhaiHook::with_limits(
            "t",
            r#"fn on_session_new(s) { let i = 0; loop { i += 1; if i > 1_000_000 { break; } } }"#,
            limits,
        )
        .unwrap();

        // Engine::set_max_operations aborts the dispatch at ~1K ops, long
        // before the loop's natural end (~5M ops).
        hook.dispatch("on_session_new", session_map(&new_session("a")));
        let spent = hook.cumulative_ops();
        assert!(
            spent < 100_000,
            "per-dispatch op cap did not trigger: {spent} ops"
        );
    }

    #[test]
    fn rhai_hook_aborts_on_wall_clock_deadline() {
        // Per-dispatch op cap disabled (0 = unlimited) and a huge cumulative
        // cap, so the 1ms deadline is the only thing that can stop the loop.
        let limits = Limits {
            max_ops_per_dispatch: 0,
            max_ops_cumulative: u64::MAX,
            deadline: Duration::from_millis(1),
            ..Limits::default()
        };
        let hook = RhaiHook::with_limits(
            "t",
            r#"fn on_session_new(s) { let i = 0; loop { i += 1; if i > 10_000_000 { break; } } }"#,
            limits,
        )
        .unwrap();

        hook.dispatch("on_session_new", session_map(&new_session("a")));
        let spent = hook.cumulative_ops();
        assert!(
            spent < 2_000_000,
            "wall-clock deadline did not abort early: {spent} ops"
        );
    }

    #[test]
    fn rhai_log_rate_limits_calls_and_bytes_per_dispatch() {
        // Call-count bound: 4 calls with a max of 2 -> 2 dropped.
        let limits = Limits {
            max_log_calls: 2,
            max_log_bytes: 1024,
            ..Limits::default()
        };
        let hook = RhaiHook::with_limits(
            "t",
            r#"fn on_session_new(s) { nyx_log("a"); nyx_log("b"); nyx_log("c"); nyx_log("d"); }"#,
            limits,
        )
        .unwrap();
        hook.dispatch("on_session_new", session_map(&new_session("a")));
        assert_eq!(hook.log_dropped(), 2);

        // Byte bound: three 5-byte messages with a 10-byte cap -> third dropped.
        let limits = Limits {
            max_log_calls: 100,
            max_log_bytes: 10,
            ..Limits::default()
        };
        let hook = RhaiHook::with_limits(
            "t",
            r#"fn on_session_new(s) { nyx_log("12345"); nyx_log("12345"); nyx_log("12345"); }"#,
            limits,
        )
        .unwrap();

        hook.dispatch("on_session_new", session_map(&new_session("a")));
        assert_eq!(hook.log_dropped(), 1);

        // The window is per dispatch: a second dispatch drops the same single
        // message again and the drop counter is cumulative across dispatches.
        hook.dispatch("on_session_new", session_map(&new_session("b")));
        assert_eq!(hook.log_dropped(), 2);
    }
}
