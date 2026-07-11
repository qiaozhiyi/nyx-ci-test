//! ⚠ NOT WIRED (P1-14): this trait exists as the seam for future JA3/JA4
//! control, but **no transport currently calls [`best()`]**. All HTTPS traffic
//! in the implant/server uses the default rustls `ClientHello`. Operators must
//! NOT assume outbound JA3 is controllable today — it is not. Wiring requires
//! the `rquest` (soon `wreq` 6.0) backend, which is pending; until it lands the
//! emitter is dead code kept only as the integration seam.
//!
//! TLS fingerprint *emission* — the seam for producing a browser-matching
//! ClientHello.
//!
//! This is the offensive complement to `tls`/`h2`: those crates *compute* a
//! fingerprint from bytes on the wire; an emitter *produces* bytes that hash to
//! a chosen fingerprint. The hard part is controlling ClientHello field order
//! (cipher suites, extensions, curves, signatures, ALPN, GREASE) at the TLS
//! stack level — pure-Rust rustls does not expose that granularity, so the
//! default emitter is "best-effort configurable", while the `rquest` feature
//! (BoringSSL) gives exact Chrome/Firefox/Safari JA3/JA4.
//!
//! The [`FingerprintEmitter`] trait is the abstraction the implant/server
//! program against; the backend is selected at compile time via the `rquest`
//! feature flag. This keeps the core pure-Rust and the browser-impersonation
//! dependency opt-in.

/// A target TLS fingerprint to impersonate. These are the common browser
/// profiles defenders allowlist; the emitter maps one to concrete ClientHello
/// construction in its backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Google Chrome (latest stable JA3/JA4 the backend ships).
    Chrome,
    /// Mozilla Firefox.
    Firefox,
    /// Apple Safari.
    Safari,
    /// A plain rustls/reqwest client (no impersonation) — useful for dev and as
    /// a fallback when no browser profile is required.
    Rustls,
}

/// The seam: something that can build a TLS client whose ClientHello matches a
/// chosen [`Profile`].
///
/// The default implementation (no `rquest` feature) is the [`DefaultEmitter`]:
/// it returns the configured profile but cannot truly impersonate a browser
/// (rustls doesn't expose ClientHello field ordering). With `rquest` enabled,
/// [`RquestEmitter`] hands back a real browser-matching client.
///
/// The trait intentionally carries no IO — it produces a connection setup; the
/// caller wires it to a transport. This keeps the trait portable and testable.
pub trait FingerprintEmitter: Send + Sync {
    /// A short label for the backend (e.g. "rustls", "rquest").
    fn backend(&self) -> &'static str;
    /// Whether this backend can exactly reproduce `profile`'s JA3/JA4. The
    /// pure-Rust default reports `false` for browser profiles; `rquest` reports
    /// `true`.
    fn can_emit(&self, profile: Profile) -> bool;
}

/// Default emitter (pure Rust, no C deps). Reports honestly that it cannot
/// exactly impersonate a browser; the implant still gets a working TLS client.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEmitter;

impl FingerprintEmitter for DefaultEmitter {
    fn backend(&self) -> &'static str {
        "rustls"
    }
    fn can_emit(&self, profile: Profile) -> bool {
        matches!(profile, Profile::Rustls)
    }
}

/// rquest-backed emitter (BoringSSL). Available with the `rquest` feature.
/// Produces exact browser JA3/JA4/Akamai H2.
#[cfg(feature = "rquest")]
#[derive(Debug, Default, Clone, Copy)]
pub struct RquestEmitter;

#[cfg(feature = "rquest")]
impl FingerprintEmitter for RquestEmitter {
    fn backend(&self) -> &'static str {
        "rquest"
    }
    fn can_emit(&self, _profile: Profile) -> bool {
        true
    }
}

/// Pick the strongest emitter compiled in. With `rquest` enabled, that's
/// [`RquestEmitter`]; otherwise [`DefaultEmitter`].
pub fn best() -> Box<dyn FingerprintEmitter> {
    #[cfg(feature = "rquest")]
    {
        Box::new(RquestEmitter)
    }
    #[cfg(not(feature = "rquest"))]
    {
        Box::new(DefaultEmitter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_emitter_is_honest_about_browser_profiles() {
        let e = DefaultEmitter;
        assert_eq!(e.backend(), "rustls");
        assert!(e.can_emit(Profile::Rustls));
        assert!(!e.can_emit(Profile::Chrome));
        assert!(!e.can_emit(Profile::Firefox));
    }

    #[test]
    fn best_picks_compiled_in_backend() {
        let e = best();
        #[cfg(feature = "rquest")]
        assert_eq!(e.backend(), "rquest");
        #[cfg(not(feature = "rquest"))]
        assert_eq!(e.backend(), "rustls");
    }
}
