//! Nyx server-side automation foundation: a typed event bus + [`Hook`] trait.
//!
//! This is the substrate that Cobalt-Strike-"Aggressor"-style automation plugs
//! into. A Lua/Rune VM (planned P3) will expose these events to operator
//! scripts (e.g. "when a new admin session pops, auto-run Seatbelt"); for now
//! the bus is directly usable from Rust via the [`Hook`] trait and the built-in
//! hooks in [`builtins`].
//!
//! Dependency-free by design (pure std + sync primitives).

pub mod builtins;
pub mod bus;
pub mod event;
pub mod hook;

pub use builtins::{FirstBloodHook, LogHook};
pub use bus::EventBus;
pub use event::{ResultKind, ResultReceived, SessionExit, SessionNew};
pub use hook::{Event, Hook};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_dispatches_to_builtin_hooks() {
        let mut bus = EventBus::new();
        let log = LogHook::new();
        let fb = FirstBloodHook::new();
        // Keep handles to the hooks' shared state before they move into the bus.
        let log_recs = log.records.clone();
        let fb_recs = fb.records.clone();
        bus.register(Box::new(log));
        bus.register(Box::new(fb));

        let session = SessionNew {
            session_id: "aa".into(),
            hostname: "ws7".into(),
            username: "admin".into(),
            os: "Windows 11".into(),
            is_admin: true,
        };
        bus.fire(&Event::SessionNew(session.clone()));
        // Same session id -> FirstBlood must NOT fire again.
        bus.fire(&Event::SessionNew(session));
        bus.fire(&Event::ResultReceived(ResultReceived {
            session_id: "aa".into(),
            task_id: 1,
            kind: ResultKind::Output,
            summary: "ok".into(),
        }));

        let log_lines = log_recs.lock().unwrap();
        let fb_lines = fb_recs.lock().unwrap();
        assert_eq!(log_lines.len(), 3, "LogHook records every event");
        assert_eq!(fb_lines.len(), 1, "FirstBlood fires once per session");
        assert!(fb_lines[0].contains("first blood"));
        assert!(fb_lines[0].contains("admin@ws7"));
    }
}
