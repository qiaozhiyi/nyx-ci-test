//! RTCore64.sys — MSI Afterburner (CVE-2019-16098).
//!
//! **Status: heavily blocklisted.** On every EDR blocklist since 2020.
//! Use only on legacy targets without vulnerable-driver blocklist enabled.
//!
//! Device: `\\.\RTCore64`
//! Read:  0x80002048
//! Write: 0x8000204C
//! Layout: 48-byte MemoryOperation, address at offset 0x08, size @ 0x18,
//!         data @ 0x1C. One byte per IOCTL (looped for multi-byte transfers).
//!
//! This is the REFERENCE driver: its protocol is the trait default
//! ([`crate::byovd::VulnDriverIoctl::raw_rw`]). The real implementation lives in
//! [`crate::byovd::RtCore64`]; this module re-exports it so the
//! `byovd_drivers::rtc64::RtCore64` path keeps working (one source of truth).

pub use crate::byovd::RtCore64;
