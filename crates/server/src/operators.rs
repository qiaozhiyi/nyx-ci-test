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
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::constant_time_eq;

/// Construct the canonical argon2id instance used for hashing new secrets.
///
/// Defaults to OWASP 2023 baseline (m=64 MiB / 65536 KiB, t=3, p=1); tunable
/// via `NYX_ARGON2_M` / `NYX_ARGON2_T` / `NYX_ARGON2_P` for hardware-specific
/// calibration. Verification reads m/t/p from each record's PHC string, so
/// existing records hashed under prior parameters still verify correctly.
fn argon2_instance() -> Argon2<'static> {
    let m_cost = std::env::var("NYX_ARGON2_M")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65536);
    let t_cost = std::env::var("NYX_ARGON2_T")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let p_cost = std::env::var("NYX_ARGON2_P")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let params = Params::new(m_cost, t_cost, p_cost, None).expect("argon2 params must be valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Run the argon2 KDF for timing equalization on missing usernames (H6), then
/// discard the result. `resolve()` returns immediately when a name isn't found,
/// but the found path runs the argon2 KDF — a remote timing oracle that lets an
/// attacker enumerate valid operator names. To close it, the not-found path
/// hashes the supplied secret against a throwaway salt here (the result is
/// always wrong, so auth still fails — but the argon2 KDF runs in BOTH paths,
/// equalizing timing).
///
/// Hashing (not verifying a pre-baked dummy) guarantees the KDF parameters
/// exactly match the found path's `argon2_instance()` regardless of how the
/// operator records were hashed — a static dummy baked at a different m/t/p
/// would re-open the timing gap.
fn run_dummy_argon2(secret: &str) {
    // A fixed dummy salt is fine: we never store or compare the output, we just
    // need the KDF to run with identical parameters as the found path. Using a
    // random salt would add OsRng jitter that itself widens the timing gap.
    static DUMMY_SALT: &[u8] = b"nyxdummytimingequalizationsalt";
    let salt = SaltString::encode_b64(DUMMY_SALT).expect("21-byte salt encodes to b64");
    let _ = argon2_instance().hash_password(secret.as_bytes(), &salt);
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
    /// On-disk registry path (when this registry was loaded from / should be
    /// flushed back to a file). `None` for in-memory test registries constructed
    /// via `empty()` / struct literals. Rehash-on-login (see [`Self::resolve`])
    /// is best-effort: when this is `None`, the in-memory record is still
    /// upgraded to argon2id but the change is not persisted.
    path: Option<std::sync::Mutex<PathBuf>>,
}

impl OperatorRegistry {
    pub fn empty() -> Self {
        Self {
            ops: RwLock::new(HashMap::new()),
            path: None,
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
    ///
    /// **Transparent rehash (OWASP password-storage pattern)**: when the matched
    /// record is a legacy `plain:<sha256>` marker AND the supplied secret
    /// verifies, the plaintext is re-hashed to argon2id and the record is
    /// updated in memory + flushed to disk (when a backing path is configured).
    /// This runs after the read lock is released — rehash needs a write lock and
    /// must not be held during the argon2 KDF (which is the slow path).
    pub fn resolve(&self, bearer: &str) -> Option<OperatorIdentity> {
        // Snapshot the matched record under a read lock, verify OUTSIDE the
        // lock, then re-acquire a write lock for the transparent rehash. This
        // avoids holding any lock during the argon2 KDF (the dominant cost) and
        // sidesteps the read→write upgrade deadlock entirely.
        let (name, secret): (&str, &str) = match bearer.split_once(':') {
            Some((n, s)) => (n, s),
            None => ("_legacy", bearer),
        };
        // `MatchedRecord` holds the minimal cloned fields we need post-unlock.
        // Cloning is cheap (name + role + a PHC string) and avoids borrowing
        // into the lock guard's lifetime.
        struct MatchedRecord {
            name: String,
            role: Role,
            secret_hash: String,
        }
        let matched: MatchedRecord = {
            let g = self.ops.read().ok()?;
            match g.get(name) {
                Some(r) => MatchedRecord {
                    name: r.name.clone(),
                    role: r.role,
                    secret_hash: r.secret_hash.clone(),
                },
                None => {
                    // Not-found path: run the dummy argon2 KDF before returning
                    // None so the timing matches the found path.
                    run_dummy_argon2(secret);
                    return None;
                }
            }
        };
        if !verify_secret(&matched.secret_hash, secret) {
            return None;
        }
        let identity = OperatorIdentity {
            name: matched.name.clone(),
            role: matched.role,
        };
        // Transparent rehash: legacy `plain:` records are upgraded to argon2id
        // on successful verification. The argon2 KDF runs here, lock-free; the
        // write lock is only taken to swap the hash + persist.
        if matched.secret_hash.starts_with("plain:") {
            self.rehash_operator(&matched.name, secret);
        }
        Some(identity)
    }

    /// Re-hash `name`'s secret to argon2id and persist. Called from
    /// [`resolve`](Self::resolve) when a legacy `plain:` record verifies
    /// successfully — this is the OWASP "rehash on next login" migration path.
    ///
    /// Acquires the write lock, swaps the `secret_hash`, then drops the lock
    /// before touching the disk (so a slow/unresponsive filesystem can't stall
    /// concurrent authentications on other operators). Persistence is
    /// best-effort: a flush failure is logged but does NOT revert the in-memory
    /// upgrade (the next successful login will retry the flush).
    fn rehash_operator(&self, name: &str, plaintext_secret: &str) {
        let new_hash = match hash_argon2(plaintext_secret) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    operator = name,
                    error = ?e,
                    "transparent rehash to argon2id failed; legacy plain: record left in place"
                );
                return;
            }
        };
        // Swap in-memory under the write lock.
        let flush_path = {
            let mut g = match self.ops.write() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!(
                        "operator registry RwLock poisoned during rehash — failing soft (no in-memory upgrade)"
                    );
                    return;
                }
            };
            let Some(rec) = g.get_mut(name) else {
                // Record vanished between read and write locks — nothing to do.
                return;
            };
            // Only upgrade if still legacy (a concurrent rehash may have won the
            // race). Idempotent under contention.
            if !rec.secret_hash.starts_with("plain:") {
                return;
            }
            rec.secret_hash = new_hash;
            self.path
                .as_ref()
                .and_then(|p| p.lock().ok().map(|g| g.clone()))
        };
        tracing::info!(
            operator = name,
            "transparent rehash: legacy plain:sha256 secret upgraded to argon2id on login"
        );
        // Flush outside the write lock. Best-effort: a failure is logged but
        // doesn't undo the in-memory upgrade (next login retries the flush).
        if let Some(path) = flush_path {
            let map: HashMap<String, OperatorRecord> = match self.ops.read() {
                Ok(g) => g.values().map(|r| (r.name.clone(), r.clone())).collect(),
                Err(_) => return,
            };
            if let Err(e) = persist(&path, &map) {
                tracing::warn!(
                    operator = name,
                    error = ?e,
                    "transparent rehash flush failed (in-memory upgrade kept; next login retries)"
                );
            }
        }
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
                // Bootstrap operator: always argon2id. The plain: fallback is
                // gone — if argon2 fails we surface the error rather than
                // silently storing an unsalted SHA-256 (the legacy weakness).
                let hash = hash_argon2(bs.1).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("bootstrap argon2 hash failed: {e}"),
                    )
                })?;
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
                // _legacy token: upgrade from plain:sha256 to argon2id. The
                // legacy plain: path remains in verify_secret only for reading
                // pre-existing records; new _legacy records are argon2id.
                let hash =
                    hash_argon2(tok).unwrap_or_else(|_| format!("plain:{}", sha256_hex(tok)));
                map.insert(
                    "_legacy".into(),
                    OperatorRecord {
                        name: "_legacy".into(),
                        secret_hash: hash,
                        role: Role::Admin,
                        created: now_secs(),
                    },
                );
                // Not persisted — _legacy is synthesized from NYX_TOKEN each boot.
            }
        }
        Ok(Self {
            ops: RwLock::new(map),
            path: Some(std::sync::Mutex::new(path.to_path_buf())),
        })
    }
}

/// Verify a secret against a stored hash. argon2 PHC strings use argon2;
/// `plain:<hex>` markers use a constant-time SHA-256 compare (legacy `_legacy`).
///
/// The `plain:` SHA-256 path is **legacy**: it is kept only for backward-
/// compatibility with operator records / `_legacy` tokens created before the
/// argon2id upgrade. New tokens are always argon2id (see `hash_argon2`). A
/// successful legacy match is transparently rehashed to argon2id by the caller
/// ([`OperatorRegistry::resolve`]) on the next login — the OWASP password-
/// storage migration pattern. The rehash warning here is a belt-and-braces
/// audit breadcrumb in case a future code path calls `verify_secret` directly.
fn verify_secret(stored: &str, secret: &str) -> bool {
    if let Some(hex) = stored.strip_prefix("plain:") {
        let got = sha256_hex(secret);
        let ok = constant_time_eq(got.as_bytes(), hex.as_bytes());
        if ok {
            tracing::warn!(
                "legacy plain:sha256 secret verified; resolve() transparently rehashes to argon2id"
            );
        }
        return ok;
    }
    match PasswordHash::new(stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Hash a secret with argon2id (OWASP baseline params) → PHC string.
fn hash_argon2(secret: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2_instance()
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
            path: None,
        };
        // named op
        let op = reg.resolve("alice:s3cret").unwrap();
        assert_eq!(op.name, "alice");
        assert!(reg.resolve("alice:wrong").is_none());
        assert!(reg.resolve("bob:s3cret").is_none());
        // legacy bare token
        let leg = reg.resolve("TOK").unwrap();
        assert_eq!(leg.name, "_legacy");
        // The first legacy resolve must have transparently rehashed the
        // in-memory `_legacy` record from plain:sha256 to argon2id. A second
        // resolve still succeeds AND the stored hash is no longer `plain:`.
        let stored_after = {
            let g = reg.ops.read().unwrap();
            g.get("_legacy").unwrap().secret_hash.clone()
        };
        assert!(
            !stored_after.starts_with("plain:"),
            "transparent rehash should have upgraded _legacy to argon2id, got: {stored_after}"
        );
        // Re-resolve — still authenticates against the now-argon2id record.
        assert!(
            reg.resolve("TOK").is_some(),
            "post-rehash legacy token must still verify"
        );
    }

    /// Verify the transparent rehash flushes to disk when a backing path is
    /// configured (the OWASP "rehash on next login" pattern). After a legacy
    /// login, the persisted file must contain an argon2id hash for the operator
    /// and reloading it must yield a registry where the record is argon2id (not
    /// `plain:`).
    #[test]
    fn resolve_transparent_rehash_flushes_to_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nyx-ops-rehash-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // Build an in-memory registry seeded with a legacy `plain:` operator
        // and a backing path, simulating a pre-argon2id file.
        let reg = OperatorRegistry {
            ops: RwLock::new({
                let mut m = HashMap::new();
                m.insert(
                    "carol".into(),
                    OperatorRecord {
                        name: "carol".into(),
                        secret_hash: format!("plain:{}", sha256_hex("legacy-secret")),
                        role: Role::Operator,
                        created: 0,
                    },
                );
                m
            }),
            path: Some(std::sync::Mutex::new(path.clone())),
        };
        // Login with the legacy secret — resolves and transparently rehashes.
        let op = reg
            .resolve("carol:legacy-secret")
            .expect("legacy login must succeed");
        assert_eq!(op.name, "carol");
        // The on-disk file must now exist and contain an argon2id hash.
        assert!(path.exists(), "rehash must flush the registry to disk");
        let reloaded = OperatorRegistry::load_or_bootstrap(&path, None, None)
            .expect("reloaded registry parses");
        let stored = {
            let g = reloaded.ops.read().unwrap();
            g.get("carol").unwrap().secret_hash.clone()
        };
        assert!(
            !stored.starts_with("plain:"),
            "persisted record must be argon2id after rehash flush, got: {stored}"
        );
        // And the reloaded registry must still authenticate carol.
        assert!(
            reloaded.resolve("carol:legacy-secret").is_some(),
            "reloaded registry must still verify the upgraded record"
        );
        let _ = std::fs::remove_file(&path);
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
