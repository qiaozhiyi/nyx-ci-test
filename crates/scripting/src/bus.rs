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
    pub fn fire(&self, event: &Event) {
        for h in &self.hooks {
            h.on_event(event);
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
