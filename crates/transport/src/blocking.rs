//! Blocking (synchronous) facade over the async BoringSSL-backed
//! impersonating client.
//!
//! The external-C2 channel implementations (`slack_api`, `discord_api`,
//! `llm_api`, `mcp`) are synchronous — they run on `ureq` and the server
//! relay drives them from `tokio::task::spawn_blocking`
//! (`crates/server/src/extc2_relay.rs`). The impersonation backend (`wreq`)
//! is async and its connect layer needs a live reactor, so this module owns
//! a private current-thread Tokio runtime per client and `block_on`s each
//! request — the same pattern `agent-dev`'s `BeaconLink` uses on the beacon
//! path.
//!
//! The whole module only exists with the `impersonation` feature: without it
//! the BoringSSL backend is absent and the default build stays hermetic (no
//! cmake/go/clang requirement).

use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::fingerprint::{
    build_impersonating_client, BrowserProfile, ImpersonatingClient, ValidateJa3Error,
};

/// A synchronous HTTP client whose TLS ClientHello + HTTP/2 frames
/// impersonate a real browser. Owns the `wreq` client plus the
/// current-thread runtime that drives it; each method blocks the calling
/// thread for the duration of the request (bounded by `timeout`).
pub struct BlockingImpersonatingClient {
    client: ImpersonatingClient,
    rt: tokio::runtime::Runtime,
}

/// Response of a [`BlockingImpersonatingClient`] request: status code plus
/// the buffered body. Mirrors the slice of `ureq::Response` the channel
/// implementations actually consume (`status` + JSON body).
pub struct BlockingResponse {
    status: u16,
    body: Vec<u8>,
}

impl BlockingImpersonatingClient {
    /// Build a client impersonating `profile`. Performs no network I/O — it
    /// only configures BoringSSL and starts the private runtime.
    pub fn new(profile: BrowserProfile) -> Result<Self, ValidateJa3Error> {
        let client = build_impersonating_client(profile)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ValidateJa3Error::Build(format!("tokio runtime: {e}")))?;
        Ok(Self { client, rt })
    }

    /// POST `body` as JSON to `url` with extra request `headers` (e.g. auth).
    /// `Content-Type: application/json` is set by the JSON body itself. The
    /// response status is NOT an error here — non-2xx classification is the
    /// caller's job (it differs per channel).
    pub fn post_json(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &serde_json::Value,
        timeout: Duration,
    ) -> Result<BlockingResponse, wreq::Error> {
        self.rt.block_on(async {
            let mut req = self.client.post(url).json(body).timeout(timeout);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let resp = req.send().await?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await?.to_vec();
            Ok(BlockingResponse { status, body })
        })
    }

    /// GET `url` with extra request `headers` and `query` params. Same
    /// status-not-an-error contract as [`Self::post_json`].
    pub fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<BlockingResponse, wreq::Error> {
        self.rt.block_on(async {
            let mut req = self.client.get(url).query(query).timeout(timeout);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let resp = req.send().await?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await?.to_vec();
            Ok(BlockingResponse { status, body })
        })
    }
}

impl BlockingResponse {
    /// HTTP status code of the response.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Deserialise the buffered body as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

// ---------------------------------------------------------------------------
// Tests — construction only, no network I/O (mirrors the feature-gated tests
// in `fingerprint.rs`). The whole module is feature-gated, so these run only
// under `--features impersonation`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Construction must succeed for every profile and must not touch the
    /// network (the client is built, never used to send a request).
    #[test]
    fn constructs_for_every_profile() {
        for profile in [
            BrowserProfile::Chrome,
            BrowserProfile::Firefox,
            BrowserProfile::Safari,
            BrowserProfile::Edge,
        ] {
            BlockingImpersonatingClient::new(profile)
                .unwrap_or_else(|e| panic!("construction failed for {profile:?}: {e}"));
        }
    }

    /// Live probe via the blocking facade: GET the TLS-echo endpoint and
    /// return the observed `(ja3_hash, ja3)` pair. Mirrors the assertion
    /// logic of `fingerprint.rs::tests::validate_ja3_live_reports_a_hash`
    /// (status 2xx + non-empty `tls.ja3_hash`).
    fn probe_ja3_blocking(profile: BrowserProfile) -> (String, String) {
        let client = BlockingImpersonatingClient::new(profile)
            .unwrap_or_else(|e| panic!("construction failed for {profile:?}: {e}"));
        let resp = client
            .get(
                crate::fingerprint::TLS_FINGERPRINT_PROBE,
                &[],
                &[],
                Duration::from_secs(30),
            )
            .unwrap_or_else(|e| panic!("{profile:?} probe request failed: {e}"));
        assert_eq!(
            resp.status(),
            200,
            "{profile:?} probe returned status {}",
            resp.status()
        );
        let body: serde_json::Value = resp
            .json()
            .unwrap_or_else(|e| panic!("{profile:?} probe response not JSON: {e}"));
        let hash = body
            .get("tls")
            .and_then(|t| t.get("ja3_hash"))
            .and_then(|h| h.as_str())
            .unwrap_or_else(|| panic!("{profile:?} probe response missing tls.ja3_hash"));
        let ja3 = body
            .get("tls")
            .and_then(|t| t.get("ja3"))
            .and_then(|j| j.as_str())
            .unwrap_or_else(|| panic!("{profile:?} probe response missing tls.ja3"));
        assert!(
            !hash.is_empty(),
            "{profile:?} ja3_hash must be non-empty — got {hash:?}"
        );
        assert!(
            !ja3.is_empty(),
            "{profile:?} ja3 must be non-empty — got {ja3:?}"
        );
        (hash.to_string(), ja3.to_string())
    }

    /// Live network probe — only runs with `--ignored`. Confirms the blocking
    /// facade really emits a fingerprintable ClientHello for Chrome (same
    /// endpoint and assertion as the async `validate_ja3_live` test).
    #[test]
    #[ignore = "hits public network (tls.peet.ws); run with --ignored"]
    fn blocking_probe_chrome_reports_a_hash() {
        let (hash, ja3) = probe_ja3_blocking(BrowserProfile::Chrome);
        eprintln!("Chrome observed JA3 hash: {hash}");
        eprintln!("Chrome observed JA3: {ja3}");
    }

    /// Live network probe — only runs with `--ignored`. Proves the blocking
    /// facade honours distinct browser profiles: Chrome and Firefox must
    /// produce different on-the-wire JA3 hashes.
    #[test]
    #[ignore = "hits public network (tls.peet.ws); run with --ignored"]
    fn blocking_probe_chrome_and_firefox_differ() {
        let (chrome_hash, chrome_ja3) = probe_ja3_blocking(BrowserProfile::Chrome);
        let (firefox_hash, firefox_ja3) = probe_ja3_blocking(BrowserProfile::Firefox);
        eprintln!("Chrome  observed JA3 hash: {chrome_hash}  ({chrome_ja3})");
        eprintln!("Firefox observed JA3 hash: {firefox_hash}  ({firefox_ja3})");
        assert_ne!(
            chrome_hash, firefox_hash,
            "Chrome and Firefox profiles must yield distinct JA3 hashes"
        );
    }
}
