//! VA-aware KernelRw over a physical-memory driver + page-table walk.
//!
//! Physical-only BYOVD drivers (e.g. WDTKernel, ALSysIO64) operate on
//! **physical** addresses. The `KernelRw` trait works in kernel **virtual**
//! addresses. The adapter that bridges them — [`VaKernelRw`] (4-level
//! VA→PA walk + per-page re-translation + the kernelsdk-2-1 address-space
//! contract) — lives in the crate-root [`crate::pagewalk`] module so its
//! mock-phys tests run on the dev host; this shell re-exports it so the
//! `win::va_rw` paths used by [`crate::win::wdt`], [`crate::win::alsys`]
//! and [`crate::win::KernelBootstrap`] stay stable.
//!
//! ## CR3 source
//! The page walk needs the kernel's CR3 (DirectoryTableBase). It is
//! discovered by [`crate::cr3_scan::discover_system_cr3`] (physical scan
//! for the System EPROCESS + MZ-validated walk of the ntoskrnl base VA),
//! driven by the phys-mode bootstraps in `win::wdt` / `win::alsys`.

pub use crate::pagewalk::{PhysRead, PhysReadError, PhysWrite, VaKernelRw};
