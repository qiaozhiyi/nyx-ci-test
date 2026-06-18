//! G2+ feature widgets. Each is a pure display widget following the
//! `SessionList` pattern (virtualized `PortalList` reading a `LazyLock<RwLock>`
//! global). Integration into the `script_mod!` DSL + the bridge's event flow
//! happens in `main.rs`.
//!
//! These were developed in parallel (one agent per file) precisely because they
//! are independent: each owns its own struct, its own global, and its own row
//! template. They share nothing except the `makepad_widgets` prelude.

pub mod bof_panel;
pub mod cred_table;
pub mod file_tree;
pub mod process_table;
