//! Windows-specific kernel-tier shells — the place future real syscall /
//! symbol-resolution bindings land. Currently empty: the algorithms in the
//! sibling modules (etwti, byovd, telemetry, persistence, netsec, offsets)
//! are platform-agnostic given a `&dyn KernelRw`; this module holds the
//! Windows-only glue that PRODUCES a `KernelRw` (BYOVD driver IOCTL binding,
//! KslD.sys bootstrap, DMA channel, driverless CVE) + symbol resolution
//! (`MmGetSystemRoutineAddress` for `EtwThreatIntProvRegHandle`, PDB RVA
//! lookup for Ps*NotifyRoutine arrays).
//!
//! ## Why it exists but is empty
//! Loading a kernel driver is operator-side + irreversible (BSOD risk) +
//! Defender-flagging. The real impls land only for an authorized target.
//! This module is the documented home so future work has a clear seam.

#![cfg(target_os = "windows")]
