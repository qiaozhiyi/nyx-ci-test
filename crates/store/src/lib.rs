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

pub use implant_store::{ImplantRecord, ImplantStore, ImplantStoreError};
pub use model::{mask_secret, CredKind, CredRecord};
pub use session_store::{SessionRecord, SessionStore, SessionStoreError};
pub use store::{CredStore, StoreError};
