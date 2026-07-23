use crate::event::{ResultReceived, SessionExit, SessionNew};

/// A discriminated event the bus delivers to hooks.
#[derive(Debug, Clone)]
pub enum Event {
    SessionNew(SessionNew),
    ResultReceived(ResultReceived),
    SessionExit(SessionExit),
}

/// Server-side automation hook. Implementations are registered on an
/// [`crate::EventBus`] and invoked for every event.
pub trait Hook: Send + Sync {
    /// Short, human-readable identifier (for logging / debugging).
    fn name(&self) -> &str;
    /// Called once per fired event. Implementations must not panic.
    fn on_event(&self, event: &Event);
}
