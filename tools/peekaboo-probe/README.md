# peekaboo-probe — the kernel side of the PeekabooProbe seam

`peekaboo_probe.c` is the signed-driver half of the Peekaboo PatchGuard window
(see `crates/operator-kernelsdk/src/persistence.rs` §3.1c and the user-mode
client in `crates/operator-kernelsdk/src/win/peekaboo.rs`). It registers a
`PsSetCreateProcessNotifyRoutineEx` callback that re-links a DKOM-hidden
process's `ActiveProcessLinks` neighbors **before** `nt!PspProcessDelete`'s
bidirectional `LIST_ENTRY` validation runs at process termination — without
it, a hidden process fast-fails with `0x139 KERNEL_SECURITY_CHECK_FAILURE`
on exit.

The driver carries **zero offset constants**: the operator-side client sends
the exact `EPROCESS` KVA and `EPROCESS + ActiveProcessOffsets` link KVA per
hidden process (`IOCTL_PEEKABOO_TRACK`), so per-build offset resolution stays
in the Rust SDK where it is PDB-backed.

**This driver cannot be built on the macOS dev host** — it needs the Windows
Driver Kit and a signing chain. The Rust user-mode side is fully implemented
and host-tested against this exact wire contract (pack/parse unit tests in
`win/peekaboo.rs`, plus a mock-transport integration test in
`crates/operator-kernelsdk/src/scenarios.rs`), so once this `.sys` is built
and signed the seam is end-to-end functional.

## Wire contract (lockstep with `win/peekaboo.rs`)

Device `\Device\PeekabooProbe`, DOS link `\??\PeekabooProbe`
(user mode opens `\\.\PeekabooProbe`). All IOCTLs are
`CTL_CODE(FILE_DEVICE_UNKNOWN, fn, METHOD_BUFFERED, FILE_ANY_ACCESS)`;
payloads are fixed-layout little-endian structs.

| IOCTL      | code       | function | in                                  | out                                                          |
|------------|------------|----------|-------------------------------------|--------------------------------------------------------------|
| HANDSHAKE  | `0x222000` | `0x800`  | `{u32 magic="PKKP", u32 version=1}` | `{u32 magic, u32 version, u32 capabilities, u32 status_flags}` |
| STATUS     | `0x222004` | `0x801`  | —                                   | `{u32 status_flags, u32 tracked_count}`                      |
| TRACK      | `0x222008` | `0x802`  | `{u64 eprocess_kva, u64 link_kva}`  | `{u32 tracked_count}`                                        |
| UNTRACK    | `0x22200C` | `0x803`  | `{u64 eprocess_kva}`                | `{u32 tracked_count}`                                        |

- `status_flags` bit0 `CALLBACK_REGISTERED`, bit1 `VALIDATION_ACTIVE`.
- `capabilities` bit0 `TERMINATION_REPAIR` (mandatory; the client refuses a
  driver without it), bit1 `VALIDATION_TRACKING`.
- TRACK is rejected unless both KVAs are canonical kernel addresses
  (`>= 0xFFFF800000000000`); a full table (64 entries) returns
  `STATUS_INSUFFICIENT_RESOURCES`. UNTRACK is idempotent.

## Build (Windows + EWDK)

1. Download the **EWDK** (Enterprise WDK) ISO matching a current SDK/WDK pair
   from Microsoft, mount it.
2. Create a KMDF/empty-kernel-driver project, or reuse the minimal
   `peekaboo_probe.vcxproj` in this directory:

   ```cmd
   :: From an EWDK "LaunchBuildEnv" cmd prompt:
   msbuild peekaboo_probe.vcxproj /p:Configuration=Release /p:Platform=x64
   ```

   Output: `x64\Release\peekaboo_probe.sys`.

## Signing (mandatory — 64-bit Windows refuses unsigned kernel code)

- **Test VM**: `bcdedit /set testsigning on`, then sign with a test cert:

  ```cmd
  signtool sign /fd sha256 /a /n "YourTestCert" x64\Release\peekaboo_probe.sys
  ```

- **Production**: the driver must pass the Microsoft Hardware Dev Center
  attestation-signing portal (EV certificate required). There is no way around
  this on Secure-Boot-enabled hosts.

## Loading / use

The operator-side CLI drives the whole seam (registry service key +
`NtLoadDriver` + device open + handshake) via the existing `driver_load`
machinery:

```cmd
nyx-kernel pg-window --peekaboo C:\path\peekaboo_probe.sys [--peekaboo-svc PeekabooProbe]
```

or, if the driver is already loaded by other means (`sc create` /
`sc start`), pass no `--peekaboo` image and the client can open
`\\.\PeekabooProbe` directly (`win::peekaboo::open_probe`).

The CLI unloads the probe driver when the window closes. Unload is also safe
manually (`sc stop`) — `DriverUnload` unregisters the callback first.
