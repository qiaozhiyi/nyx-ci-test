# WP: Beacon inject family (RW→RX fail-closed)

## Files

- `crates/bof-runner/src/inject.rs` (new) — host-testable sequencer: RW alloc → write → RX protect → `CreateRemoteThread` at `base+offset`. Recording double locks protect-before-thread and forbids RWX (`0x40`).
- `crates/bof-runner/src/shim.rs` — `BeaconInjectProcess` / `BeaconInjectTemporaryProcess`. `VirtualAllocEx` RW (`0x04`) → `WriteProcessMemory` → `VirtualProtectEx` RX (`0x20`) → `CreateRemoteThread`. Protect/write/alloc failure frees the remote region and never threads. NULL `hProc` opens `pid` with `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION` (`0x042A`). `BeaconInjectTemporaryProcess` uses `pInfo->hProcess` and does **not** resume the primary thread. CS is `void`; shims return `BOOL` like spawn/token so failure is observable (`SetLastError` / Win32 last-error).
- `crates/bof-runner/src/layout.rs` — both names in `BEACON_APIS`; `VirtualAllocEx` / `VirtualProtectEx` / `VirtualFreeEx` / `WriteProcessMemory` / `CreateRemoteThread` added to `EXTERN_SINGLES` for BOF imports.
- `crates/bof-runner/src/win.rs` — trampoline `beacon_shim_addr` arms.
- `crates/bof-runner/src/lib.rs` — `mod inject`; crate docs.
- `crates/bof-host/src/lib.rs`, `crates/bof-host/src/shim.rs` — comments only. PIC host keeps inject **named Unresolved** (kernel32 is not mapped in the sacrificial child; an ntdll-only `NtCreateThreadEx` chain would break no-write-static / PIC dumper constraints). Implemented in std `bof-runner`.

## Tests

Host (`cargo test -p nyx-bof-runner`): 20 passed, including sequencer order (`alloc, write, protect, thread`), protect-fail never threads, RW then RX constants, ABI registration / unique names.

wine64 (`CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine64 cargo test -p nyx-bof-runner --target x86_64-pc-windows-gnu`): 69 passed. Live-fire: spawn suspended `cmd.exe` → inject 1-byte `0xC3` (`ret`) via `BeaconInjectTemporaryProcess` + `BeaconInjectProcess(hProc)` (OpenProcess(pid) noted if the prefix refuses it) → terminate + `BeaconCleanupProcess`. Fail-closed null/OOB cases set `GetLastError`.

Clippy: `cargo clippy -p nyx-bof-runner --all-targets -- -D warnings` and the same with `--target x86_64-pc-windows-gnu`. `cargo fmt -p nyx-bof-runner`.

## Leftovers

- PIC `bof-host` / isolated sacrificial child: inject family still named Unresolved (intentional).
- `implant-tasks` inline `bof.rs` shim table was not expanded (out of scope).
- CS community `beacon.h` also passes `int a_len` after `arg` and copies the arg blob after the payload. This shim treats `arg` as the remote thread parameter and does not append an arg region (x64 extra stack slot from 7-arg callers is ignored).
- `BeaconFormatAlloc` / format family still unimplemented.
- Spawn-to path remains the hardcoded `C:\Windows\System32\cmd.exe` writable buffer.
- No wait on the remote thread (CS does not wait); live-fire success is `CreateRemoteThread` returning a handle.
- Did not edit `CHANGELOG.md` / `README.md` / `docs/STATUS.md`.
