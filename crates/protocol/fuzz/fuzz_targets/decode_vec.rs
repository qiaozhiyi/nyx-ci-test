// Fuzz harness for the attacker-facing wire-format decoder of nyx-protocol.
//
// Threat model: on the team server `panic = "abort"` is set, so ANY unhandled
// decode path in a beacon body (a decrypted-but-arbitrary byte string) kills the
// process = a DoS. The contract this harness polices is therefore absolute:
//   decoding arbitrary input MUST either return Ok(..) or Err(..) — never panic.
// A panic in `Task::decode_vec` / `TaskResponse::decode_vec` / any `Reader`
// method is a crash == a real bug.
//
// We fuzz three surfaces over the same fuzzer corpus:
//   1. `Task::decode_vec`        — server->implant task batches
//   2. `TaskResponse::decode_vec` — implant->server result batches
//   3. raw `Reader` methods       — the u8/u16/u32/u64/blob/str primitives that
//      `decode_vec` is built on; `blob`/`str` read a u32 length prefix and then
//      that many bytes, the classic allocation-bomb / bounds vector.
//
// The harness is split with a single byte prefix so the corpus covers all three
// without one starving the others. Input layout: `[tag][rest]`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nyx_protocol::msg::{Task, TaskResponse};
use nyx_protocol::wire::Reader;

fuzz_target!(|data: &[u8]| {
    // Need at least the routing tag.
    if data.is_empty() {
        let _ = Task::decode_vec(data);
        let _ = TaskResponse::decode_vec(data);
        return;
    }
    let (tag, rest) = data.split_first().unwrap();

    match tag % 4 {
        // 1) Task batch (server -> implant).
        0 => {
            let _ = Task::decode_vec(rest);
        }
        // 2) TaskResponse batch (implant -> server).
        1 => {
            let _ = TaskResponse::decode_vec(rest);
        }
        // 3) Raw Reader length-prefixed reads — the u32-prefixed blob/str paths
        //    that the allocation-bomb guards (MAX_BATCH / checked_count) sit in
        //    front of. Walk the cursor to completion to exercise take()/u32().
        2 => {
            let mut r = Reader::new(rest);
            // Alternate blob/str/u32 reads until the input is exhausted or an
            // Err is returned. Every step must be Err-or-Ok, never a panic.
            let mut which = 0u8;
            loop {
                let step = match which % 3 {
                    0 => r.blob().map(|_| ()),
                    1 => r.str().map(|_| ()),
                    _ => r.u32().map(|_| ()),
                };
                if step.is_err() {
                    break;
                }
                which = which.wrapping_add(1);
                if r.remaining() == 0 {
                    break;
                }
            }
            // Also poke the fixed-width readers; they're trivially bounds-checked
            // but cost nothing to exercise on the same corpus.
            let mut r2 = Reader::new(rest);
            let _ = r2.u8();
            let _ = r2.u16();
            let _ = r2.u64();
        }
        // 4) Both batch decoders on the same input (cross-checks that nothing
        //    about decode_vec for one type interferes when run back-to-back).
        _ => {
            let _ = Task::decode_vec(rest);
            let _ = TaskResponse::decode_vec(rest);
        }
    }
});
