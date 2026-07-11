# Nyx Fix Batches — Shared Context (2026-07-08)

## Status
- **Batch A (crypto) DONE** — `protocol/crypto.rs` already changed: `random_bytes` returns Result, `generate()` returns `Result<Self, GenerateError>`, zero-scalar rejected, HKDF uses `server_pub` as salt, SessionKey has real `Drop` + redacted `Debug` (no longer `Copy`). All callers updated. Tests pass.
- **DO NOT touch `crates/protocol/src/crypto.rs`** — it's done.

## Build constraints
- Workspace builds on macOS host: `cargo build --workspace` (std crates).
- `crates/implant-win` is NOT a workspace member; builds standalone on Windows nightly. On macOS, only `cargo check -p nyx-protocol --no-default-features` validates the no_std protocol crate. Implant-win changes are verified by `cargo check` where possible; full implant build requires Windows.
- After your changes: run `cargo build --workspace` and `cargo test -p <your-crate>` to verify. Do NOT run the full workspace test suite (2 pre-existing theme test failures in client-cli are unrelated).
- `panic = "abort"` in the implant (release profile). Server uses `panic = "unwind"`.

## Fix plan reference
See `docs/FIX_PLAN_2026-07-08.md` for detailed fix instructions with authoritative references (RFC/official docs) for each finding.

## Critical conventions
- Keep changes MINIMAL and surgical. Fix the specific bug, don't refactor surrounding code.
- Preserve existing code style (comments, naming conventions).
- Every fix must include or update a test where feasible.
- Do NOT add new dependencies unless the fix plan explicitly calls for it.
- Use `edit` tool for surgical changes; `write` only for new files.
- If a fix is blocked by something unexpected, document it and move to the next fix in your batch.
