//! Named-operator identity + registry (Phase 3 v1).
//!
//! Replaces the single shared `NYX_TOKEN` bearer with per-operator identity so
//! the audit log can attribute every action to a named operator. Each operator
//! has a name + an argon2-hashed secret + a role; the client sends
//! `Authorization: Bearer <name>:<secret>` (the `:` delimiter is unambiguous —
//! names forbid `:`). See the `nyx-operators-audit-design` workflow.
//!
//! ## Backward compatibility (load-bearing)
//! - If a registry file is loaded with ≥1 operator → multi-op mode: the bearer
//!   must be `name:secret`, verified per-operator via argon2.
//! - Else if `NYX_TOKEN` is set → legacy mode: a synthetic `_legacy` admin
//!   record matches the bare token via a `plain:` SHA-256 marker, so every
//!   existing client keeps working byte-for-byte.
//! - Else → open mode (dev/CI): every request is allowed as `_anonymous`.
//!
//! The registry persists to a JSON file (atomic temp+rename, 0600 — mirroring
//! `load_or_create_keypair`). The first admin is bootstrapped from
//! `NYX_BOOTSTRAP_OPERATOR=name:secret` when the registry is empty.

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::constant_time_eq;

/// Pre-computed dummy argon2id hash for timing equalization on missing
/// usernames (H6). `resolve()` returns immediately when a name isn't found, but
/// runs the argon2 KDF for an existing one — a remote timing oracle that lets
/// an attacker enumerate valid operator names. To close it, the not-found path
/// verifies the supplied secret against this dummy hash first (the result is
/// always wrong, so auth still fails — but the argon2 KDF runs in BOTH paths,
/// equalizing timing). This is a real argon2id PHC string generated with
/// `Argon2::default()` (m=19456, t=2, p=1) so `PasswordHash::new` parses it and
/// the verifier does full work; the salt+hash correspond to a throwaway value,
/// not any operator credential.
const DUMMY_ARGON2_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$avsslxbZ8H9a70Oz4U8X2A$wyQB2YXwW8o/KHkgNgVa93jV2hezrFS9XtUiRh/p1eA";

/// Run the argon2 KDF against the dummy hash, discarding the result. Used on
/// the username-not-found path of `resolve()` to equalize timing with the
/// found path (which runs argon2 to verify the real secret). Parsing the PHC
/// string is cached in a `OnceLock` so only the first miss pays the parse cost;
/// subsequent misses share the parsed hash (the KDF still runs every time, which
/// is the whole point). A parse failure (impossible for this constant, but
/// defended against so a future edit can't panic the server under
/// `panic = "abort"`) simply skips the dummy work.
fn run_dummy_argon2(secret: &str) {
    static DUMMY: std::sync::OnceLock<Option<PasswordHash>> = std::sync::OnceLock::new();
    let parsed = DUMMY.get_or_init(|| PasswordHash::new(DUMMY_ARGON2_HASH).ok());
    if let Some(h) = parsed {
        let _ = Argon2::default().verify_password(secret.as_bytes(), h);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRecord {
    pub name: String,
    /// argon2 PHC string, OR `plain:<sha256hex>` for the legacy `_legacy` marker.
    pub secret_hash: String,
    pub role: Role,
    #[serde(default)]
    pub created: u64,
}

/// The identity an authenticated request resolves to — threaded into handlers so
/// each audited action records WHO acted.
#[derive(Debug, Clone)]
pub struct OperatorIdentity {
    pub name: String,
    pub role: Role,
}

pub struct OperatorRegistry {
    ops: RwLock<HashMap<String, OperatorRecord>>,
}

impl OperatorRegistry {
    pub fn empty() -> Self {
        Self {
            ops: RwLock::new(HashMap::new()),
        }
    }

    /// `true` when no operators are loaded (open mode — every request allowed
    /// as `_anonymous`). Used by `authenticate` to short-circuit to the legacy
    /// token / open paths.
    ///
    /// # Panic / poison safety
    ///
    /// A poisoned `RwLock` means a thread panicked while holding the write lock.
    /// Treat poisoning as a security event: **fail CLOSED** and refuse all
    /// authentication rather than silently falling back to open mode.
    pub fn is_open(&self) -> bool {
        match self.ops.read() {
            Ok(g) => g.is_empty(),
            Err(_) => {
                tracing::error!("operator registry RwLock poisoned — failing CLOSED");
                false
            }
        }
    }

    /// Resolve a bearer value to an identity. Accepts `name:secret` (multi-op)
    /// or a bare token (matched against the `_legacy` record, if any).
    ///
    /// Timing equalization (H6): when the username is not found, the argon2 KDF
    /// would otherwise be skipped entirely, making the found-vs-not-found paths
    /// distinguishable by wall-clock time — a remote oracle for enumerating
    /// valid operator names. On every not-found path we run the argon2 KDF
    /// against [`DUMMY_ARGON2_HASH`] (result discarded) so both paths pay the
    /// same dominant cost.
    pub fn resolve(&self, bearer: &str) -> Option<OperatorIdentity> {
        let g = self.ops.read().ok()?;
        if let Some((name, secret)) = bearer.split_once(':') {
            // Not-found path: run the dummy argon2 KDF before returning None so
            // the timing matches the found path (which verifies a real hash).
            let rec = match g.get(name) {
                Some(r) => r,
                None => {
                    run_dummy_argon2(secret);
                    return None;
                }
            };
            return verify_secret(&rec.secret_hash, secret).then(|| OperatorIdentity {
                name: rec.name.clone(),
                role: rec.role,
            });
        }
        // Bare token → legacy `_legacy` record. Same dummy-KDF equalization when
        // no `_legacy` record exists (e.g. a name was supplied without a colon
        // but no legacy token was configured).
        let rec = match g.get("_legacy") {
            Some(r) => r,
            None => {
                run_dummy_argon2(bearer);
                return None;
            }
        };
        verify_secret(&rec.secret_hash, bearer).then(|| OperatorIdentity {
            name: "_legacy".into(),
            role: rec.role,
        })
    }

    pub fn list(&self) -> std::io::Result<Vec<OperatorRecord>> {
        self.ops
            .read()
            .map(|g| g.values().cloned().collect())
            .map_err(|_| {
                eprintln!("FATAL: operator registry RwLock poisoned — refusing to operate");
                std::io::Error::other("operator registry RwLock poisoned")
            })
    }

    /// Load the registry from `path`. If the file is absent/empty:
    /// - bootstrap one admin from `bootstrap` (`name:secret`) when set, else
    /// - synthesize a `_legacy` admin from `nyx_token` (plain SHA-256 marker),
    /// - else return an empty (open) registry.
    pub fn load_or_bootstrap(
        path: &Path,
        nyx_token: Option<&str>,
        bootstrap: Option<&str>,
    ) -> std::io::Result<Self> {
        let mut map: HashMap<String, OperatorRecord> = if path.exists() {
            let txt = std::fs::read_to_string(path)?;
            let parsed: Vec<OperatorRecord> = serde_json::from_str(&txt).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("operators file parse error: {e}"),
                )
            })?;
            parsed.into_iter().map(|r| (r.name.clone(), r)).collect()
        } else {
            HashMap::new()
        };

        if map.is_empty() {
            if let Some(bs) = bootstrap.and_then(|s| {
                let (n, sec) = s.split_once(':')?;
                (!n.is_empty() && !sec.is_empty()).then_some((n, sec))
            }) {
                let hash =
                    hash_argon2(bs.1).unwrap_or_else(|_| format!("plain:{}", sha256_hex(bs.1)));
                map.insert(
                    bs.0.to_string(),
                    OperatorRecord {
                        name: bs.0.to_string(),
                        secret_hash: hash,
                        role: Role::Admin,
                        created: now_secs(),
                    },
                );
                persist(path, &map)?;
                tracing::info!(
                    operator = bs.0,
                    "bootstrapped admin operator from NYX_BOOTSTRAP_OPERATOR"
                );
            } else if let Some(tok) = nyx_token.filter(|s| !s.is_empty()) {
                map.insert(
                    "_legacy".into(),
                    OperatorRecord {
                        name: "_legacy".into(),
                        secret_hash: format!("plain:{}", sha256_hex(tok)),
                        role: Role::Admin,
                        created: now_secs(),
                    },
                );
                // Not persisted — _legacy is synthesized from NYX_TOKEN each boot.
            }
        }
        Ok(Self {
            ops: RwLock::new(map),
        })
    }
}

/// Verify a secret against a stored hash. argon2 PHC strings use argon2;
/// `plain:<hex>` markers use a constant-time SHA-256 compare (legacy `_legacy`).
fn verify_secret(stored: &str, secret: &str) -> bool {
    if let Some(hex) = stored.strip_prefix("plain:") {
        let got = sha256_hex(secret);
        return constant_time_eq(got.as_bytes(), hex.as_bytes());
    }
    match PasswordHash::new(stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Hash a secret with argon2 → PHC string.
fn hash_argon2(secret: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(secret.as_bytes(), &salt)?
        .to_string())
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Atomic write (temp + rename, 0600 on Unix) — mirrors `load_or_create_keypair`.
fn persist(path: &Path, map: &HashMap<String, OperatorRecord>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let rows: Vec<&OperatorRecord> = map.values().collect();
    let json = serde_json::to_vec_pretty(&rows).map_err(io_err)?;
    let tmp = path.with_extension("json.tmp");
    use std::fs::OpenOptions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut file = opts.open(&tmp)?;
    file.write_all(&json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip() {
        let h = hash_argon2("hunter2").unwrap();
        assert!(verify_secret(&h, "hunter2"));
        assert!(!verify_secret(&h, "wrong"));
    }

    #[test]
    fn plain_marker_constant_time() {
        let h = format!("plain:{}", sha256_hex("tok"));
        assert!(verify_secret(&h, "tok"));
        assert!(!verify_secret(&h, "nope"));
    }

    #[test]
    fn resolve_named_and_legacy() {
        let reg = OperatorRegistry {
            ops: RwLock::new({
                let mut m = HashMap::new();
                m.insert(
                    "alice".into(),
                    OperatorRecord {
                        name: "alice".into(),
                        secret_hash: hash_argon2("s3cret").unwrap(),
                        role: Role::Admin,
                        created: 0,
                    },
                );
                m.insert(
                    "_legacy".into(),
                    OperatorRecord {
                        name: "_legacy".into(),
                        secret_hash: format!("plain:{}", sha256_hex("TOK")),
                        role: Role::Admin,
                        created: 0,
                    },
                );
                m
            }),
        };
        // named op
        let op = reg.resolve("alice:s3cret").unwrap();
        assert_eq!(op.name, "alice");
        assert!(reg.resolve("alice:wrong").is_none());
        assert!(reg.resolve("bob:s3cret").is_none());
        // legacy bare token
        let leg = reg.resolve("TOK").unwrap();
        assert_eq!(leg.name, "_legacy");
    }

    #[test]
    fn bootstrap_writes_admin_then_reloads() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nyx-ops-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let reg = OperatorRegistry::load_or_bootstrap(&path, None, Some("alice:hunter2")).unwrap();
        assert!(!reg.is_open());
        assert!(reg.resolve("alice:hunter2").is_some());
        assert!(path.exists(), "bootstrap must persist the registry");
        // Reload WITHOUT the bootstrap env (file already has alice) → no double-bootstrap.
        let reg2 = OperatorRegistry::load_or_bootstrap(&path, None, Some("bob:ignored")).unwrap();
        assert!(reg2.resolve("alice:hunter2").is_some());
        assert!(
            reg2.resolve("bob:ignored").is_none(),
            "bootstrap env ignored once registry non-empty"
        );
        let _ = std::fs::remove_file(&path);
    }
}
