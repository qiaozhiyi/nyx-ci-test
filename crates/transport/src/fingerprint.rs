//! TLS fingerprint *emission* — the seam for producing a browser-matching
//! ClientHello + HTTP/2 SETTINGS frame.
//!
//! This is the *emission* side. The *computation/verification* side lives in
//! [`crate::tls`] (JA3/JA4 from a parsed ClientHello) and [`crate::h2`] (Akamai
//! fingerprint from an HTTP/2 preface).
//!
//! # Backend status (2026-07)
//!
//! Emission requires a BoringSSL-backed HTTP client that can control
//! ClientHello field ordering — the pure-Rust rustls/reqwest stack cannot do
//! this. The intended backend is [`rquest`](https://crates.io/crates/rquest)
//! (or its successor `wreq`), a BoringSSL fork of reqwest with pre-built
//! browser TLS/HTTP/2 presets.
//!
//! **However, every published `rquest` version is currently yanked on
//! crates.io.** Until a non-yanked version (or a git pin) is available, this
//! module provides the full API surface and mapping logic WITHOUT pulling in
//! the yanked dependency. When `rquest` is resolvable, add the `impersonation`
//! feature to `Cargo.toml` and implement the `build_impersonating_client`
//! function body.

/// Coarse-grained browser family to impersonate.
///
/// Each variant maps to a concrete, recent stable preset of the underlying
/// BoringSSL backend. The mapping is kept in one place (see
/// [`profile_to_preset_name`]) so the pinned browser version can be bumped
/// without touching call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserProfile {
    /// Google Chrome (Chromium) — the most common real-browser TLS fingerprint
    /// on the public web, and therefore the safest default for blending in.
    Chrome,
    /// Mozilla Firefox — distinct TLS extension ordering / ciphers from Chrome.
    Firefox,
    /// Apple Safari — macOS/iOS native fingerprint; pairs well with a macOS
    /// implant host for locality-plausible traffic.
    Safari,
    /// Microsoft Edge (Chromium-based, but ships its own HTTP/2 SETTINGS).
    Edge,
}

impl BrowserProfile {
    /// Human-readable name of the concrete preset version this profile maps to
    /// under the current backend.
    pub const fn latest_version(self) -> &'static str {
        match self {
            BrowserProfile::Chrome => "Chrome131",
            BrowserProfile::Firefox => "Firefox135",
            BrowserProfile::Safari => "Safari18",
            BrowserProfile::Edge => "Edge131",
        }
    }

    /// Family name without the version suffix (e.g. "Chrome", not "Chrome131").
    pub const fn family(self) -> &'static str {
        match self {
            BrowserProfile::Chrome => "Chrome",
            BrowserProfile::Firefox => "Firefox",
            BrowserProfile::Safari => "Safari",
            BrowserProfile::Edge => "Edge",
        }
    }
}

impl std::fmt::Display for BrowserProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.latest_version())
    }
}

/// Map a coarse [`BrowserProfile`] to the concrete preset name string that the
/// BoringSSL backend uses internally (e.g. `"Chrome131"` for rquest's
/// `Impersonate::Chrome131`).
///
/// Centralising this mapping is the point of the module: bumping a pinned
/// browser version (e.g. Chrome131 → Chrome136) is a one-line change here and
/// automatically flows to every caller.
///
/// Pure function — does no I/O and touches no backend state, so it is fully
/// unit-testable without network or a BoringSSL toolchain.
pub fn profile_to_preset_name(profile: BrowserProfile) -> &'static str {
    profile.latest_version()
}

/// Endpoint used by [`validate_ja3`] to observe the on-the-wire fingerprint.
pub const TLS_FINGERPRINT_PROBE: &str = "https://tls.peet.ws/api/all";

/// Errors returned by [`validate_ja3`].
#[derive(Debug)]
pub enum ValidateJa3Error {
    /// The fingerprint backend (`rquest`) is not available — all published
    /// versions are yanked. Re-enable when a non-yanked version is published.
    BackendUnavailable,
    /// The HTTP request to the probe endpoint failed (network, TLS, or status).
    Http(String),
    /// The response body could not be parsed as the expected JSON shape.
    MalformedProbeResponse(String),
}

impl std::fmt::Display for ValidateJa3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidateJa3Error::BackendUnavailable => write!(
                f,
                "TLS fingerprint backend (rquest) not available — all versions yanked on crates.io"
            ),
            ValidateJa3Error::Http(msg) => write!(f, "probe HTTP request failed: {msg}"),
            ValidateJa3Error::MalformedProbeResponse(msg) => {
                write!(f, "malformed probe response: {msg}")
            }
        }
    }
}

impl std::error::Error for ValidateJa3Error {}

/// Build an HTTP client whose TLS ClientHello and HTTP/2 frames impersonate
/// the requested browser family.
///
/// **Currently returns `BackendUnavailable`** — the `rquest` crate (BoringSSL
/// browser impersonation) has all versions yanked on crates.io. The mapping
/// logic ([`profile_to_preset_name`]) and API surface are ready; only the
/// backend wiring needs the dependency to be resolvable.
///
/// When a non-yanked `rquest` is available, add it as an optional dependency
/// and implement this function body:
///
/// ```ignore
/// pub fn build_impersonating_client(profile: BrowserProfile) -> Result<rquest::Client, ValidateJa3Error> {
///     let preset = match profile {
///         BrowserProfile::Chrome => rquest::tls::Impersonate::Chrome131,
///         BrowserProfile::Firefox => rquest::tls::Impersonate::Firefox135,
///         BrowserProfile::Safari => rquest::tls::Impersonate::Safari18,
///         BrowserProfile::Edge => rquest::tls::Impersonate::Edge131,
///     };
///     rquest::Client::builder()
///         .impersonate(preset)
///         .connect_timeout(std::time::Duration::from_secs(30))
///         .build()
///         .map_err(|e| ValidateJa3Error::Http(e.to_string()))
/// }
/// ```
pub fn build_impersonating_client(_profile: BrowserProfile) -> Result<(), ValidateJa3Error> {
    Err(ValidateJa3Error::BackendUnavailable)
}

/// Hit a public TLS-echo service and return the JA3 string the server *observed*
/// from the client.
///
/// **Currently returns `BackendUnavailable`** — requires the `rquest` backend.
pub async fn validate_ja3(_client: &()) -> Result<String, ValidateJa3Error> {
    Err(ValidateJa3Error::BackendUnavailable)
}

// ---------------------------------------------------------------------------
// Tests — all network-free, exercising only the pure mapping logic.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The public enum must cover exactly the four browser families.
    #[test]
    fn browser_profile_has_four_variants() {
        let all = [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "variant {i:?} should equal itself");
                } else {
                    assert_ne!(a, b, "variants {i:?} and {j:?} must differ");
                }
            }
        }
        assert_eq!(all.len(), 4, "exactly four browser profiles expected");
    }

    /// `profile_to_preset_name` must map each family to a preset whose name
    /// starts with the family name. Catches copy-paste mistakes.
    #[test]
    fn profile_maps_to_matching_family_preset() {
        for profile in [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ] {
            let preset = profile_to_preset_name(profile);
            let family = profile.family();
            assert!(
                preset.starts_with(family),
                "{profile:?} mapped to {preset:?}, which does not start with family name {family:?}"
            );
        }
    }

    /// `latest_version` and `family` must be consistent.
    #[test]
    fn latest_version_starts_with_family() {
        for profile in [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ] {
            let version = profile.latest_version();
            let family = profile.family();
            assert!(
                version.starts_with(family),
                "{profile:?}.latest_version() = {version:?}, expected to start with {family:?}"
            );
        }
    }

    /// `build_impersonating_client` must gracefully report backend-unavailable
    /// rather than panicking or hanging.
    #[test]
    fn build_client_reports_backend_unavailable() {
        let result = build_impersonating_client(BrowserProfile::Chrome);
        assert!(matches!(result, Err(ValidateJa3Error::BackendUnavailable)));
    }

    /// Display impl outputs the version string.
    #[test]
    fn display_outputs_version() {
        assert_eq!(BrowserProfile::Chrome.to_string(), "Chrome131");
        assert_eq!(BrowserProfile::Firefox.to_string(), "Firefox135");
    }

    /// The probe URL constant is the expected peet.ws endpoint.
    #[test]
    fn probe_url_is_peet_ws() {
        assert!(TLS_FINGERPRINT_PROBE.starts_with("https://tls.peet.ws/"));
    }
}
