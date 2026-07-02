//! Rhai scripting hook — the pure-Rust Aggressor-script equivalent.
//!
//! Chose Rhai (pure Rust, no C) over Lua: `mlua`'s `Lua` is `!Send` and would
//! need a dedicated worker thread, whereas Rhai's `Engine` is `Send + Sync`, so
//! a [`RhaiHook`] implements [`Hook`] directly with no thread isolation.
//!
//! Loads a Rhai script and dispatches [`nyx_scripting::Event`]s to script
//! functions `on_session_new(s)`, `on_result(r)`, `on_session_exit(e)`, passing
//! each event as a Rhai `Map`. Exposes a `nyx_log(msg)` API.

use std::sync::Arc;

use nyx_scripting::event::{ResultReceived, SessionExit, SessionNew};
use nyx_scripting::hook::{Event, Hook};
use rhai::{Dynamic, Engine, EvalAltResult, Map, Scope, AST};

/// A scripting hook backed by a (shared) Rhai engine + a compiled script.
pub struct RhaiHook {
    name: String,
    engine: Arc<Engine>,
    ast: AST,
}

impl RhaiHook {
    /// Compile `source` (which may define `on_*` handlers and use `nyx_log`).
    pub fn new(name: &str, source: &str) -> Result<Self, Box<EvalAltResult>> {
        let mut engine = Engine::new();
        // Resource caps: a buggy or hostile operator script runs inline on the
        // server (the EventBus fires hooks from beacon handlers). Without caps
        // `loop {}` stalls the request and unbounded string growth OOMs. These
        // are generous for any real handler but bound the worst case.
        engine
            .set_max_call_levels(64) // recursion / call depth
            .set_max_operations(1_000_000) // ~loop iterations per dispatch
            .set_max_string_size(64 * 1024) // no unbounded string concatenation
            .set_max_array_size(4096)
            .set_max_variables(512)
            .set_max_functions(64)
            .set_max_expr_depths(32, 32); // expression / statement nesting
        engine.register_fn("nyx_log", |msg: String| {
            eprintln!("[nyx-rhai] {msg}");
        });
        let ast = engine.compile(source)?;
        Ok(Self {
            name: name.to_string(),
            engine: Arc::new(engine),
            ast,
        })
    }

    fn dispatch(&self, handler: &str, payload: Map) {
        // Missing handler -> Err; that's fine (a script need not handle every event).
        let mut scope = Scope::new();
        let _ = self
            .engine
            .call_fn::<()>(&mut scope, &self.ast, handler, (payload,));
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
mod tests {
    use super::*;
    use nyx_scripting::EventBus;
    use std::sync::atomic::{AtomicU64, Ordering};

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
        bus.fire(&Event::SessionNew(SessionNew {
            session_id: "a".into(),
            hostname: "ws7".into(),
            username: "u".into(),
            os: "Windows".into(),
            is_admin: false,
        }));
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
}
