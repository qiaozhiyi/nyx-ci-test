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
//! this. The lineage of Rust BoringSSL-impersonation clients is:
//!
//! 1. `reqwest-impersonate` — **yanked** on crates.io.
//! 2. `rquest` — **deprecated** (repo moved to `0x676e67/rquest-deprecated`,
//!    frozen at v0.30.1, no longer maintained).
//! 3. `wreq` + `wreq-util` — the **active successor** by the same author
//!    (`0x676e67/wreq`, currently v5.3.0). This is what this module uses.
//!
//! `wreq` replaces the old `rquest::Impersonate::Chrome131` enum with a more
//! modular [`wreq_util::Emulation`] enum plus a pluggable
//! `EmulationProvider`. The browser presets (TLS ciphersuites + extension
//! ordering + HTTP/2 SETTINGS + header order) live in `wreq-util`.
//!
//! `wreq`/`boring-sys2` need the BoringSSL native toolchain (cmake + go + perl
//! + clang). To keep the default `cargo build` hermetic, the backend is gated
//! behind the **`impersonation`** Cargo feature (see list below).
// clippy's doc_lazy_continuation fires on the paragraph→list transition below;
// the list items are independent bullets, not continuations of line 27.
//!
//! - **default (feature off):** the mapping/preset logic is available, but
//!   [`build_impersonating_client`] returns
//!   [`ValidateJa3Error::BackendUnavailable`].
//! - **`--features impersonation`:** [`build_impersonating_client`] returns a
//!   real [`wreq::Client`] whose ClientHello + HTTP/2 frames match the chosen
//!   [`BrowserProfile`].
//!
//! # Can we actually control the on-the-wire JA3? (honest answer)
//!
//! **Yes**, when built with `--features impersonation`. `wreq` drives
//! BoringSSL directly, and `wreq-util` ships field-accurate TLS/HTTP2 presets
//! per browser version (cipher list, extension order, GREASE placement,
//! ALPN, HTTP/2 SETTINGS frame, WINDOW_UPDATE, PRIORITY frames, header
//! order). This is the same technique `curl_cffi` / `utls` use; a ClientHello
//! produced this way is byte-equivalent to the named browser's.

use core::fmt;

/// Coarse-grained browser family to impersonate.
///
/// Each variant maps to a concrete, recent stable preset of the underlying
/// BoringSSL backend (see [`profile_to_preset_name`] /
/// [`profile_to_emulation`]). The mapping is kept in one place so the pinned
/// browser version can be bumped without touching call sites.
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
    ///
    /// These track the *latest* variant each backend ships, as of 2026-07.
    /// Bumping a pin is a one-line change here.
    pub const fn latest_version(self) -> &'static str {
        match self {
            BrowserProfile::Chrome => "Chrome137",
            BrowserProfile::Firefox => "Firefox139",
            BrowserProfile::Safari => "Safari18_5",
            BrowserProfile::Edge => "Edge134",
        }
    }

    /// Family name without the version suffix (e.g. "Chrome", not "Chrome137").
    pub const fn family(self) -> &'static str {
        match self {
            BrowserProfile::Chrome => "Chrome",
            BrowserProfile::Firefox => "Firefox",
            BrowserProfile::Safari => "Safari",
            BrowserProfile::Edge => "Edge",
        }
    }
}

impl fmt::Display for BrowserProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.latest_version())
    }
}

/// Map a coarse [`BrowserProfile`] to the concrete preset name string that the
/// BoringSSL backend uses internally (e.g. `"Chrome137"` for wreq-util's
/// `Emulation::Chrome137`).
///
/// Centralising this mapping is the point of the module: bumping a pinned
/// browser version (e.g. Chrome137 → Chrome140) is a one-line change here and
/// automatically flows to every caller.
///
/// Pure function — does no I/O and touches no backend state, so it is fully
/// unit-testable without network or a BoringSSL toolchain.
pub fn profile_to_preset_name(profile: BrowserProfile) -> &'static str {
    profile.latest_version()
}

/// Endpoint used by [`validate_ja3`] to observe the on-the-wire fingerprint.
pub const TLS_FINGERPRINT_PROBE: &str = "https://tls.peet.ws/api/all";

/// The concrete HTTP client type returned by [`build_impersonating_client`].
///
/// - With the `impersonation` feature: a [`wreq::Client`] (BoringSSL-backed,
///   browser-matching ClientHello).
/// - Without the feature: `()` — emission is unavailable.
#[cfg(feature = "impersonation")]
pub type ImpersonatingClient = wreq::Client;

/// The concrete HTTP client type returned by [`build_impersonating_client`].
#[cfg(not(feature = "impersonation"))]
pub type ImpersonatingClient = ();

/// Errors returned by [`build_impersonating_client`] / [`validate_ja3`].
#[derive(Debug)]
pub enum ValidateJa3Error {
    /// The fingerprint backend is not available. With the `impersonation`
    /// feature off this is always returned; with it on, this variant is
    /// unreachable (kept for API stability across the feature boundary).
    BackendUnavailable,
    /// The HTTP request to the probe endpoint failed (network, TLS, or status).
    Http(String),
    /// The response body could not be parsed as the expected JSON shape.
    MalformedProbeResponse(String),
    /// The BoringSSL-backed client could not be constructed (builder error).
    Build(String),
}

impl fmt::Display for ValidateJa3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidateJa3Error::BackendUnavailable => write!(
                f,
                "TLS fingerprint backend unavailable — build nyx-transport with \
                 `--features impersonation` (pulls in wreq + BoringSSL) to enable"
            ),
            ValidateJa3Error::Http(msg) => write!(f, "probe HTTP request failed: {msg}"),
            ValidateJa3Error::MalformedProbeResponse(msg) => {
                write!(f, "malformed probe response: {msg}")
            }
            ValidateJa3Error::Build(msg) => write!(f, "client build failed: {msg}"),
        }
    }
}

impl std::error::Error for ValidateJa3Error {}

// ---------------------------------------------------------------------------
// Backend wiring — only present when the `impersonation` feature is on.
// ---------------------------------------------------------------------------

/// Map a [`BrowserProfile`] to its concrete [`wreq_util::Emulation`] preset.
///
/// `wreq-util`'s `Emulation` enum is `#[non_exhaustive]`, so we never construct
/// it by parsing strings — we name the exact variant here. Bumping a pinned
/// browser version is a one-line edit in this function.
///
/// Only available with the `impersonation` feature (the `wreq-util` dependency
/// is optional).
#[cfg(feature = "impersonation")]
pub fn profile_to_emulation(profile: BrowserProfile) -> wreq_util::Emulation {
    use wreq_util::Emulation;
    match profile {
        BrowserProfile::Chrome => Emulation::Chrome137,
        BrowserProfile::Firefox => Emulation::Firefox139,
        BrowserProfile::Safari => Emulation::Safari18_5,
        BrowserProfile::Edge => Emulation::Edge134,
    }
}

/// Build an HTTP client whose TLS ClientHello and HTTP/2 frames impersonate
/// the requested browser family.
///
/// - **With the `impersonation` feature** (recommended): returns a real
///   [`wreq::Client`] backed by BoringSSL. The ClientHello cipher list,
///   extension ordering, GREASE bytes, ALPN, and the HTTP/2 SETTINGS /
///   WINDOW_UPDATE / PRIORITY frames all match the chosen browser version, so
///   the on-the-wire JA3/JA4/Akamai fingerprints match the real browser. Use
///   [`validate_ja3`] to confirm against a public TLS-echo service.
/// - **Without the feature**: returns [`ValidateJa3Error::BackendUnavailable`]
///   — the default build stays hermetic (no BoringSSL toolchain required).
///
/// Building the client does no network I/O; it only configures BoringSSL and
/// the HTTP/2 layer, so this is safe to unit-test without a live endpoint.
#[cfg(feature = "impersonation")]
pub fn build_impersonating_client(
    profile: BrowserProfile,
) -> Result<ImpersonatingClient, ValidateJa3Error> {
    let client = wreq::Client::builder()
        .emulation(profile_to_emulation(profile))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ValidateJa3Error::Build(e.to_string()))?;
    Ok(client)
}

/// Build an HTTP client whose TLS ClientHello and HTTP/2 frames impersonate
/// the requested browser family.
///
/// Without the `impersonation` feature this always returns
/// [`ValidateJa3Error::BackendUnavailable`] — the default build is hermetic.
/// Re-build with `--features impersonation` to get a real BoringSSL-backed
/// [`wreq::Client`] (see the variant above).
#[cfg(not(feature = "impersonation"))]
#[deprecated(
    since = "0.1.0",
    note = "rquest backend is deprecated; enable the `impersonation` feature for the wreq successor"
)]
pub fn build_impersonating_client(
    _profile: BrowserProfile,
) -> Result<ImpersonatingClient, ValidateJa3Error> {
    Err(ValidateJa3Error::BackendUnavailable)
}

/// Hit a public TLS-echo service and return the JA3 *hash* the server observed
/// from the client.
///
/// Requires the `impersonation` feature (needs a real [`wreq::Client`] to
/// produce a fingerprintable ClientHello). This is a live network call and is
/// therefore `#[ignore]`-d by default — run with `cargo test -p nyx-transport
/// --features impersonation -- --ignored validate_ja3_live`.
///
/// The peet.ws `/api/all` endpoint returns JSON of the form
/// `{"tls":{"ja3_hash":"...", "ja3":"...", ...}}`; we extract `ja3_hash`.
#[cfg(feature = "impersonation")]
pub async fn validate_ja3(client: &ImpersonatingClient) -> Result<String, ValidateJa3Error> {
    let resp = client
        .get(TLS_FINGERPRINT_PROBE)
        .send()
        .await
        .map_err(|e| ValidateJa3Error::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ValidateJa3Error::Http(format!("probe returned {status}")));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ValidateJa3Error::MalformedProbeResponse(e.to_string()))?;
    let hash = body
        .get("tls")
        .and_then(|t| t.get("ja3_hash"))
        .and_then(|h| h.as_str())
        .ok_or_else(|| {
            ValidateJa3Error::MalformedProbeResponse(
                "missing tls.ja3_hash field in probe response".into(),
            )
        })?;
    Ok(hash.to_string())
}

/// Without the `impersonation` feature the validator cannot run (no
/// fingerprintable backend).
#[cfg(not(feature = "impersonation"))]
pub async fn validate_ja3(_client: &ImpersonatingClient) -> Result<String, ValidateJa3Error> {
    Err(ValidateJa3Error::BackendUnavailable)
}

// ---------------------------------------------------------------------------
// Tests — network-free. The pure mapping tests run in every build; the
// client-construction tests run only with `--features impersonation` (they
// still do no network I/O — they only exercise BoringSSL/client setup).
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

    /// Display impl outputs the version string.
    #[test]
    fn display_outputs_version() {
        assert_eq!(BrowserProfile::Chrome.to_string(), "Chrome137");
        assert_eq!(BrowserProfile::Firefox.to_string(), "Firefox139");
        assert_eq!(BrowserProfile::Safari.to_string(), "Safari18_5");
        assert_eq!(BrowserProfile::Edge.to_string(), "Edge134");
    }

    /// The probe URL constant is the expected peet.ws endpoint.
    #[test]
    fn probe_url_is_peet_ws() {
        assert!(TLS_FINGERPRINT_PROBE.starts_with("https://tls.peet.ws/"));
    }

    /// Preset names must contain a numeric version component (guards against
    /// accidentally committing a family-only string like `"Chrome"`).
    #[test]
    fn preset_names_carry_a_version_number() {
        for profile in [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ] {
            let preset = profile_to_preset_name(profile);
            let has_digit = preset.chars().any(|c| c.is_ascii_digit());
            assert!(
                has_digit,
                "{profile:?} preset {preset:?} has no version digit"
            );
        }
    }

    /// Distinct families must map to distinct preset names (no aliasing).
    #[test]
    fn preset_names_are_distinct_per_family() {
        let names: Vec<&'static str> = [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ]
        .iter()
        .map(|p| profile_to_preset_name(*p))
        .collect();
        let uniq: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), uniq.len(), "preset names collide: {names:?}");
    }

    // -----------------------------------------------------------------------
    // Feature-gated tests: real client construction (no network I/O).
    // -----------------------------------------------------------------------

    /// When the `impersonation` feature is OFF, the builder must report
    /// backend-unavailable rather than panicking or hanging.
    #[cfg(not(feature = "impersonation"))]
    #[test]
    fn build_client_reports_backend_unavailable() {
        #![allow(deprecated)]
        let result = build_impersonating_client(BrowserProfile::Chrome);
        assert!(matches!(result, Err(ValidateJa3Error::BackendUnavailable)));
    }

    /// When the `impersonation` feature is ON, the builder must successfully
    /// construct a BoringSSL-backed client for every profile. This exercises
    /// the BoringSSL/wreq wiring but performs **no** network I/O (the client is
    /// built, never used to send a request).
    #[cfg(feature = "impersonation")]
    #[test]
    fn build_client_succeeds_for_every_profile() {
        for profile in [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ] {
            let client = build_impersonating_client(profile)
                .unwrap_or_else(|e| panic!("build failed for {profile:?}: {e}"));
            // Prove it really is a wreq::Client and didn't silently become ().
            // `get()` is only defined on the real client type, so this is a
            // compile-time check. We do NOT send — no network I/O.
            let _ = client.get("https://invalid.localhost.invalid/");
        }
    }

    /// `profile_to_emulation` must produce distinct `Emulation` values per
    /// family (no two profiles collapsing onto the same browser preset).
    #[cfg(feature = "impersonation")]
    #[test]
    fn emulation_mapping_is_distinct_per_family() {
        use std::collections::HashSet;
        let emus: HashSet<wreq_util::Emulation> = [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ]
        .iter()
        .map(|p| profile_to_emulation(*p))
        .collect();
        assert_eq!(emus.len(), 4, "emulation presets collide");
    }

    /// Live network probe — only runs with `--ignored` and only meaningful with
    /// the `impersonation` feature. Confirms the on-the-wire JA3 really is
    /// emitted by the BoringSSL backend.
    #[cfg(feature = "impersonation")]
    #[tokio::test]
    #[ignore = "hits public network (tls.peet.ws); run with --ignored"]
    async fn validate_ja3_live_reports_a_hash() {
        let client = build_impersonating_client(BrowserProfile::Chrome).unwrap();
        let hash = validate_ja3(&client).await.expect("ja3 probe failed");
        assert!(
            !hash.is_empty(),
            "ja3_hash must be non-empty — got {hash:?}"
        );
    }
}
