//! Proxy VEH handler registration — REMOVED (2026-08, gadget-consumption
//! audit, task I1).
//!
//! This module previously carried two fully-implemented but never-consumed
//! evasion prototypes:
//!
//! - **Mode A — `jmp rbx` / `call rbx` gadget scan.** Gadgets in
//!   ntdll/kernelbase/kernel32 were scanned and cached at init, but no flow
//!   ever used them. The documented consumers (Micro-Stager INT3, Fluctuation
//!   thunk HWBP restore) do not exist in the codebase, and Mode A is
//!   architecturally unusable for the one live VEH flow (`blind_hwbp`): a
//!   CPU-triggered #DB fires with an uncontrolled RBX, so a `jmp rbx` proxy
//!   handler can never reach the real handler — which is exactly why Mode B
//!   was drafted.
//! - **Mode B — section-backed handler** (`\KnownDlls\ntdll.dll` SEC_IMAGE
//!   view + code-cave trampoline). Zero callers, and its premise fails the
//!   scanner model it targeted: the handler address lands in a second image
//!   mapping that is NOT in the PEB loader list, so VEH-chain scanners that
//!   check "handler inside a legitimately loaded module" still flag it —
//!   while writing the trampoline flips an image page RW/RWX, a larger IOC
//!   than the direct registration it replaced (see
//!   docs/audits/FULL_CODE_AUDIT_2026-07-21.md).
//!
//! The active HWBP/VEH path registers `blind_hwbp::hwbp_veh_handler`
//! directly via `AddVectoredExceptionHandler`, CFG-marked through
//! `cfg_user::mark_addr_cfg_valid`.
//!
//! This module shell is kept (empty) because the shell cdylib
//! (`nyx-implant-win`) re-exports `proxy_veh` by name. The removed code is
//! recoverable from git history if an engagement ever needs it.
