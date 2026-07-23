//! IQVW64E.sys — Intel Ethernet diagnostics (CVE-2015-2291, kdmapper driver).
//!
//! **Status: blocklisted.** Less flagged than RTCore64 historically,
//! but on the Microsoft Vulnerable Driver Blocklist since 2023.
//!
//! Device: `\\.\iqvw64e`
//!
//! **Protocol (verified against TheCruZ/kdmapper `intel_driver.cpp`):** a SINGLE
//! dispatch IOCTL `0x80862007` handles every operation; the request's
//! `case_number` field selects it. Memory R/W uses case `0x33` (MemCopy) with a
//! 40-byte `COPY_MEMORY_BUFFER_INFO` struct, and the driver performs an
//! arbitrary-length kernel-side `memcpy(destination, source, length)`.
//!   - Read  = MemCopy(dst = user buf, src = kernel addr)
//!   - Write = MemCopy(dst = kernel addr, src = user buf)
//! No per-byte loop (unlike RTCore64).
//!
//! The real implementation (including the `raw_rw` override) lives in
//! [`crate::byovd::Iqvw64e`]; this module re-exports it so the
//! `byovd_drivers::iqvw64e::Iqvw64e` path keeps working (one source of truth —
//! a prior version of this file carried a second, divergent copy that asserted
//! wrong IOCTL codes 0x80802010/0x80802014 and never overrode the RTCore64
//! byte-loop, so reads/writes were silently wrong).

pub use crate::byovd::Iqvw64e;
