use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::hook::{Event, Hook};

/// An ordered collection of [`Hook`]s, fired together.
///
/// Registration (`register`) requires `&mut self`, so do it at construction
/// time before the bus is shared (`Arc`-wrapped). Firing (`fire`) only takes
/// `&self`, so it is safe to call from shared contexts (e.g. concurrent axum
/// handlers); hooks are responsible for their own internal synchronization.
pub struct EventBus {
    hooks: Vec<Box<dyn Hook>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    pub fn register(&mut self, hook: Box<dyn Hook>) {
        self.hooks.push(hook);
    }

    /// Deliver `event` to every registered hook, in registration order.
    ///
    /// Each hook invocation is isolated with [`catch_unwind`] so one panicking
    /// hook cannot starve the remaining hooks (or unwind the caller's request
    /// handler). The panic is logged with the hook's `name()` and delivery
    /// continues with the next hook. NOTE: the workspace release profile is
    /// `panic = "abort"` (root Cargo.toml), under which `catch_unwind` cannot
    /// intercept — hooks must still be panic-free in release; this boundary is
    /// defense-in-depth for dev/test (unwinding) builds and for any future
    /// unwinding profile.
    pub fn fire(&self, event: &Event) {
        for h in &self.hooks {
            let name = h.name().to_string();
            let result = catch_unwind(AssertUnwindSafe(|| h.on_event(event)));
            if let Err(payload) = result {
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("unknown panic payload");
                eprintln!(
                    "[scripting] hook `{name}` panicked while handling an event; \
                     skipping it and continuing: {msg}"
                );
            }
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
