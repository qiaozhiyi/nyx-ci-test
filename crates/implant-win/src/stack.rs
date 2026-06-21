//! Call-stack spoofing — research-grade skeleton.
//!
//! ## Status: SKELETON — not wired into syscall invocations.
//!
//! EDRs walk the call stack of a sensitive syscall (NtOpenProcess, NtAllocate-
//! VirtualMemory, …) and flag a return address that doesn't live inside a
//! legit module (a bare indirect-syscall trampoline still returns into implant
//! memory). Stack spoofing (Ethradjius "spoof", mrexodia ThreadStackSpoofer)
//! fabricates a fake legit-looking call chain (e.g. a sequence of ntdll/
//! kernelbase frames terminating at our syscall) so the walk sees plausible
//! return addresses.
//!
//! The correct implementation requires per-syscall-call setup: allocate a fake
//! frame region, write a chain of `jmp [rax]`/`ret` gadgets from legit modules,
//! swap RSP to it before the syscall, and restore after. That's tightly coupled
//! to the indirect-syscall trampoline in [`crate::syscalls`] and can't be safely
//! added without runtime testing — a bad frame swap corrupts RSP and crashes.
//!
//! This module exposes the [`with_spoofed_stack`] seam the runtime WILL call
//! once the implementation lands, with a no-op body today so the codebase stays
//! correct. The indirect syscall already executes from inside ntdll (the
//! `syscall` instruction's RIP is legit), so the current OPSEC posture is
//! "syscall RIP is real, return address is implant" — spoofing closes the
//! second half.

#![cfg(target_os = "windows")]

/// Execute `f` with a spoofed call stack.
///
/// **Today**: a direct call to `f()` with no stack manipulation. The contract
/// (returns whatever `f` returns) is fixed so `syscalls::syscallN` can wrap its
/// trampoline invocation in `stack::with_spoofed_stack(|| ...)` when the full
/// implementation lands without changing call sites.
///
/// # Safety
/// Marked unsafe because the real implementation will manipulate the stack
/// pointer and return addresses; callers must treat `f` as running under unusual
/// stack conditions.
pub unsafe fn with_spoofed_stack<T>(f: impl FnOnce() -> T) -> T {
    // No-op: call f directly. The syscall RIP is already legit (inside ntdll);
    // only the return address is implant-allocated. Full spoof lands later.
    f()
}
