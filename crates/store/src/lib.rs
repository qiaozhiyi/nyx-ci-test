//! Persistent credential store for the Nyx team server.
//!
//! Server-side, std-only. Backed by SQLite (WAL, ACID) via `rusqlite` (bundled
//! libsqlite3-sys — compiles from source, no system sqlite3). NEVER enters the
//! `no_std` PIC implant; it is pulled only by the server (and, for the MODEL
//! types only, by the operator clients).
//!
//! The canonical [`CredRecord`] + [`CredKind`] live HERE so the server + both
//! clients agree on one shape (killing the prior triplicate cred-model drift —
//! see `nyx-rest`'s `SessionView` for the same pattern).

pub mod implant_store;
pub mod model;
pub mod session_store;
pub mod store;

use std::path::Path;
// `PathBuf` is only used by the Unix-only `set_private` helper (set_mode is
// `std::os::unix`); on Windows the import would be unused under -D warnings.
#[cfg(unix)]
use std::path::PathBuf;

pub use implant_store::{ImplantRecord, ImplantStore, ImplantStoreError};
pub use model::{mask_secret, CredKind, CredRecord};
pub use session_store::{SessionRecord, SessionStore, SessionStoreError};
pub use store::{CredStore, StoreError};

/// Best-effort `chmod 0600` on the DB file and any `-wal`/`-shm` siblings
/// (Unix only). Non-fatal — the store still opens. SQLite creates new
/// `-wal`/`-shm` files with the same mode as the DB file, so 0600-ing the DB
/// covers later siblings, but a pre-existing world-readable `-wal` (created
/// before the first chmod) must not leak — hence the sibling sweep. Every
/// store calls this after `open` (the team-server disk is a single
/// high-value target).
#[cfg(unix)]
pub(crate) fn set_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    for suffix in ["-wal", "-shm"] {
        let mut os = path.as_os_str().to_owned();
        os.push(suffix);
        let p = PathBuf::from(os);
        if let Ok(meta) = std::fs::metadata(&p) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&p, perms);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_private(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
