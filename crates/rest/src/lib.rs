//! Shared REST view types + operator-client helpers.
//!
//! This is the single source of truth for the JSON shapes the team server emits
//! on `/api/*`, and for the tiny client-side helpers every operator client
//! needs (`authed`, `session_signature`, `arch_name`). It exists because those
//! types/helpers used to be hand-mirrored in client-ui (`bridge.rs`),
//! client-cli (`rest.rs`/`types.rs`), and the egui client — and all three copies
//! had already drifted: every client's `SessionView` silently dropped
//! `age_secs`/`ja3`/`ja4`, and the two `arch` byte→string mappings disagreed with
//! each other AND with the protocol definition.
//!
//! Centralising here makes that drift structurally impossible: fix a view field
//! or a helper once, every client gets it.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

// ---- view types (mirror the server's REST output, ALL fields) ------------
//
// Every field is `#[serde(default)]` so a server that adds a field doesn't
// break older clients, and a client upgrade that hasn't yet learned a new field
// degrades gracefully instead of failing the whole request.

/// One beacon session, as returned by `GET /api/sessions`. Field-for-field with
/// `server::SessionView` (the serializer), including `age_secs`/`ja3`/`ja4`
/// which prior client copies silently dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SessionView {
    pub id: String,
    #[serde(default)]
    pub beacon_id: u32,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: u8,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub is_admin: u8,
    #[serde(default)]
    pub pending: usize,
    /// Seconds since the session first checked in (server-side clock).
    #[serde(default)]
    pub age_secs: u64,
    /// Inbound TLS JA3 (MD5 hex), if the ClientHello sniffer captured one.
    #[serde(default)]
    pub ja3: Option<String>,
    /// Inbound TLS JA4 (FoxIO `a_b_c`), if captured.
    #[serde(default)]
    pub ja4: Option<String>,
    /// `true` when the session was restored from the persistent store at boot
    /// and has NOT beaconed since the restart — i.e. its last_seen is from a
    /// prior server lifetime, so the operator sees it flagged as potentially
    /// gone. Cleared to `false` on the first live check-in after boot.
    #[serde(default)]
    pub stale: bool,
}

/// Ack for `POST /api/task`: the assigned task id (and, for `Connect`, the
/// server-allocated channel id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAck {
    pub task_id: u64,
    #[serde(default)]
    pub chan: Option<u32>,
}

/// One task result row from `GET /api/results`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultView {
    pub task_id: u64,
    pub kind: String,
    pub text: String,
    #[serde(default)]
    pub data_hex: Option<String>,
    #[serde(default)]
    pub seq: Option<u32>,
    #[serde(default)]
    pub eof: Option<u8>,
}

// ---- helpers -------------------------------------------------------------

/// Human architecture tag from the `SessionInfo.arch` wire byte. Matches the
/// protocol definition (`crates/protocol/src/msg.rs`): **0 = x86_64, 1 = aarch64,
/// 2 = x86**. (Both clients had previously drifted to different — and mutually
/// disagreeing — schemes; this is the authoritative mapping.)
pub fn arch_name(a: u8) -> &'static str {
    match a {
        0 => "x64",
        1 => "arm64",
        2 => "x86",
        _ => "?",
    }
}

/// One pending-task row from `GET /api/tasks`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskView {
    pub task_id: u64,
    pub command: String,
}

/// `GET /api/profile` — the active Malleable C2 profile summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileView {
    pub loaded: bool,
    #[serde(default)]
    pub http_get_uri: Option<String>,
    #[serde(default)]
    pub http_post_uri: Option<String>,
    #[serde(default)]
    pub useragent: Option<String>,
}

/// Attach the bearer API token to a request when one is configured; pass the
/// request through unchanged otherwise. `/beacon` is exempt (implants auth
/// cryptographically), so this is only for the operator control API.
pub fn authed(req: reqwest::RequestBuilder, token: &Option<String>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

/// A cheap, stable signature of a session list for change detection — the
/// worker only pushes a UI snapshot when this string changes. Deliberately
/// excludes `age_secs` (which churns every second) so the UI doesn't flap on
/// every poll tick.
pub fn session_signature(list: &[SessionView]) -> String {
    let mut s = String::new();
    for v in list {
        s.push_str(&v.id);
        s.push('|');
        s.push_str(&v.hostname);
        s.push('|');
        s.push_str(&v.username);
        s.push('|');
        s.push_str(&format!("{}|{}", v.is_admin, v.pending));
        s.push(';');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_name_matches_protocol_definition() {
        // crates/protocol/src/msg.rs: 0 = x86_64, 1 = aarch64, 2 = x86.
        assert_eq!(arch_name(0), "x64");
        assert_eq!(arch_name(1), "arm64");
        assert_eq!(arch_name(2), "x86");
        assert_eq!(arch_name(255), "?");
    }

    #[test]
    fn session_view_decodes_all_server_fields_including_fingerprints() {
        // The drift bug: clients dropped age_secs/ja3/ja4. This pins that they
        // decode (serde would silently ignore them if the fields were absent).
        let json = r#"{"id":"deadbeef","beacon_id":4660,"hostname":"h","username":"u","os":"linux","arch":1,"pid":42,"is_admin":1,"pending":3,"age_secs":99,"ja3":"aabb","ja4":"t13-d0400-00-00"}"#;
        let v: SessionView = serde_json::from_str(json).unwrap();
        assert_eq!(v.beacon_id, 4660);
        assert_eq!(v.age_secs, 99);
        assert_eq!(v.ja3.as_deref(), Some("aabb"));
        assert_eq!(v.ja4.as_deref(), Some("t13-d0400-00-00"));
    }

    #[test]
    fn session_signature_is_stable_and_ignores_age() {
        let mk = |age: u64| SessionView {
            id: "s1".into(),
            hostname: "h".into(),
            username: "u".into(),
            is_admin: 0,
            pending: 1,
            age_secs: age,
            ..Default::default()
        };
        // age changes must NOT change the signature (else the UI redraws/sec).
        assert_eq!(session_signature(&[mk(0)]), session_signature(&[mk(999)]));
    }
}
