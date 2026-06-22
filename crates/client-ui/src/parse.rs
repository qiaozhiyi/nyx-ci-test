//! Thin adapter over [`nyx_parse`] — the shared shell-output parser crate.
//!
//! The actual parsing logic (field-skip counts, CSV splitting, locale sniffing)
//! lives in `crates/parse/src/lib.rs` exactly once. This module only maps the
//! neutral rows (`FileRow`/`ProcRow`/`CredRow`) onto client-ui's own widget
//! types. Centralising the parsers there kills the twin-copy drift hazard: a
//! parser bug fixed in `nyx-parse` is fixed for every client, with no risk of
//! one copy being silently left behind (which is how the `parse_ps_posix`
//! off-by-one survived for as long as it did).

use crate::widgets::cred_table::{CredEntry, CredKind};
use crate::widgets::file_tree::FileEntry;
use crate::widgets::process_table::ProcEntry;

pub fn parse_any_files(out: &str) -> Vec<FileEntry> {
    nyx_parse::parse_any_files(out)
        .into_iter()
        .map(FileEntry::from)
        .collect()
}

pub fn parse_any_procs(out: &str) -> Vec<ProcEntry> {
    nyx_parse::parse_any_procs(out)
        .into_iter()
        .map(ProcEntry::from)
        .collect()
}

pub fn parse_creds(out: &str) -> Vec<CredEntry> {
    nyx_parse::parse_creds(out)
        .into_iter()
        .map(CredEntry::from)
        .collect()
}

// ---- neutral-row → widget-type mappings ----------------------------------
//
// `FileEntry`/`ProcEntry`/`CredEntry` are local to this crate (defined in the
// widget modules), so these `From<foreign>` impls satisfy the orphan rule.

impl From<nyx_parse::FileRow> for FileEntry {
    fn from(r: nyx_parse::FileRow) -> Self {
        Self {
            name: r.name,
            size: r.size,
            is_dir: r.is_dir,
            modified: r.modified,
        }
    }
}

impl From<nyx_parse::ProcRow> for ProcEntry {
    fn from(r: nyx_parse::ProcRow) -> Self {
        // `arch` is a UI-only display field the parser doesn't carry; default
        // to 255 ("?"), matching the old inline parser's behaviour.
        Self {
            pid: r.pid,
            ppid: r.ppid,
            name: r.name,
            user: r.user,
            arch: 255,
        }
    }
}

impl From<nyx_parse::CredRow> for CredEntry {
    fn from(r: nyx_parse::CredRow) -> Self {
        Self {
            source: r.source,
            principal: r.principal,
            kind: CredKind::from(r.kind),
            secret: r.secret,
        }
    }
}

impl From<nyx_parse::Kind> for CredKind {
    fn from(k: nyx_parse::Kind) -> Self {
        match k {
            nyx_parse::Kind::Hash => CredKind::Hash,
            nyx_parse::Kind::Password => CredKind::Password,
            nyx_parse::Kind::Ticket => CredKind::Ticket,
            nyx_parse::Kind::Key => CredKind::Key,
        }
    }
}
