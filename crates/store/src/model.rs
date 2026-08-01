//! The ONE canonical credential model for Nyx — shared by the team server
//! (which persists it) and both operator clients (which POST/render it).
//!
//! This replaces the prior triplicate drift: `nyx_parse::CredRow` (the parser's
//! neutral row — stays), `client-cli::types::CredEntry`, and `client-ui`'s own
//! serde-less `CredEntry` (both deleted, re-exported from here). See
//! [[nyx-duplicate-parser-hazard]].
//!
//! Field map (CS parity): `realm` = CS realm/domain, `user` = CS user/principal,
//! `secret` = CS password or hash, `kind` discriminates them, `source` =
//! tactic+beacon that produced it, `beacon` = session that dumped it (optional,
//! creds outlive the beacon), `collected_at` = Unix-secs, `notes` = free text.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredKind {
    Hash,
    Password,
    Ticket,
    Key,
}

impl CredKind {
    /// Stable lowercase label used as the SQLite `kind` column value + the
    /// `/api/creds/{...}/{kind}` segment. Round-trips via [`CredKind::from_label`].
    pub fn label(self) -> &'static str {
        match self {
            CredKind::Hash => "hash",
            CredKind::Password => "password",
            CredKind::Ticket => "ticket",
            CredKind::Key => "key",
        }
    }

    /// Inverse of [`CredKind::label`]. `None` on an unknown label (the caller
    /// surfaces a 400, never panics — the server runs `panic=abort`).
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "hash" => Some(CredKind::Hash),
            "password" => Some(CredKind::Password),
            "ticket" => Some(CredKind::Ticket),
            "key" => Some(CredKind::Key),
            _ => None,
        }
    }
}

/// One stored credential. The composite key is `(realm, user, kind)` — a
/// re-dump of the same user@realm+kind UPSERTS (updates the secret in place),
/// matching Cobalt Strike's credential tab semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredRecord {
    pub realm: String,
    pub user: String,
    pub kind: CredKind,
    pub secret: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub beacon: Option<String>,
    #[serde(default)]
    pub collected_at: u64,
    #[serde(default)]
    pub notes: String,
}

/// Mask a secret for list/preview rendering: `first2….last2` when long enough,
/// else a bare `…. Sentinel for "this view is masked; call ?reveal=1 for
/// cleartext". UTF-8-safe (char-based, not byte-slice): byte slicing would
/// panic on a multi-byte char boundary, so masking operates on `char`s.
pub fn mask_secret(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 4 {
        "....".to_string()
    } else {
        let prefix: String = chars[..2].iter().collect();
        let suffix: String = chars[chars.len() - 2..].iter().collect();
        format!("{prefix}....{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_label_roundtrip() {
        for k in [
            CredKind::Hash,
            CredKind::Password,
            CredKind::Ticket,
            CredKind::Key,
        ] {
            assert_eq!(CredKind::from_label(k.label()), Some(k));
        }
        assert_eq!(CredKind::from_label("bogus"), None);
    }

    #[test]
    fn mask_long_and_short() {
        assert_eq!(mask_secret("8846f7eaee8fb117ad06bdd830b7586c"), "88....6c");
        assert_eq!(mask_secret("ab"), "....");
        assert_eq!(mask_secret(""), "....");
    }

    #[test]
    fn mask_non_ascii_no_panic() {
        // Regression: the old implementation sliced byte ranges (`&s[..2]`),
        // which is NOT a char boundary for multi-byte UTF-8 and panicked.
        // Char-based masking must never panic and must mask the first/last
        // two *characters*.
        assert_eq!(mask_secret("pässwörd-ünïcode"), "pä....de");
        assert_eq!(mask_secret("日本語文書"), "日本....文書");
        assert_eq!(mask_secret("日本語文"), "...."); // exactly 4 chars
        assert_eq!(mask_secret("日本語"), "...."); // 3 chars
        assert_eq!(mask_secret("aä"), "...."); // 2 chars, multi-byte
    }
}
