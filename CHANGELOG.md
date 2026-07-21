# Changelog

All notable changes to the Nyx C2 framework are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0` is treated as a pre-release internal state that was never officially tagged;
`0.2.0` is the first shipped release. Entries cite the originating commit short-SHA so
operators can `git show` the exact change. Evidence is authoritative over prose — when
this file and the code disagree, the code wins.

## [Unreleased]

## [0.3.2] - 2026-07-22

Second round of audit fixes — closes the remaining 13 CRITICAL findings
from the 2026-07-21 full-codebase audit. With v0.3.1 + v0.3.2 combined,
**all 27 CRITICAL findings are closed**. The only remaining audit item is
CRITICAL-19 (beacon task isolation), which is an architectural change
deferred to v0.4.0.

### Fixed (13 CRITICAL)

- **crypto `.expect()` → `Result` (CRITICAL-1/2 + HIGH).** `hkdf_sha256`,
  `seal_dir`, `seal`, `encode_frame`/`encode_frame_dir`, and
  `config::decrypt` now return `Result` instead of panicking under
  `panic="abort"`. All ~27 call sites updated: server propagates via
  `anyhow`; implant exits with diagnostic codes (`0xC3`, `0xA7`,
  `0xB8-BA`, `0xC000_0002`); `embed!` proc-macro keeps a build-time
  `.expect()` (correct signal for a broken-build fixture). New
  `HkdfError` enum (no new deps). 16 files, +306/-105.
- **blind_hwbp `static mut` UB + VEH lock-contention kill (CRITICAL-6/7).**
  Eliminated all `static mut` declarations; replaced with `AtomicU8` per-slot
  state machine (`VACANT`/`OCCUPIED`/`CLAIMED`), `AtomicPtr` for handles,
  `SyncUnsafeCell` for the fixed backing store. VEH handler is now fully
  lock-free — returns `EXCEPTION_CONTINUE_SEARCH` only for genuine "not our
  #DB" (null pointer, no DR6 bits, address mismatch), never for lock
  contention. Arming/disarming uses CAS + Release publication so the VEH
  never observes an armed entry without a matching DR bit.
- **stack.rs `assume_init`/`forget(f)` UB (CRITICAL-8).** Added
  `AtomicBool SWAP_DONE` set by `run_f_on_spoof` after `ptr::read(f)`.
  Only `forget(f)` + `assume_init()` if `SWAP_DONE`; otherwise `drop(f)` +
  return `T::default()`. `FAKE_STACK` bumped from 2 KiB to 8 KiB. Added
  `T: Default` bound (all existing callers satisfy it).
- **lacuna_stomp uninitialized slice UB (CRITICAL-9).** Replaced
  `Vec::with_capacity + forget + from_raw_parts_mut` (uninit slots) with
  `extend_from_slice + as_mut_ptr + forget` (initialized before detach).
  OOM check on `capacity >= len`. Capped `MAX_GHOST_DEPTH = 32`;
  `frames_len * 8` → `checked_mul`.
- **keylog `BUF`/`BUF_LEN` data race (CRITICAL-12).** Moved
  `HOOK_THREAD_LIVE` publication into the hook thread (after
  `SetWindowsHookExW`, before the message pump). New CAS-based
  `claim_buf_index()` gives single-writer-per-byte semantics. Polling path
  re-checks `hook_is_active()` per-byte. Drain uses `BUF_LEN.swap(0,
  AcqRel)`.
- **screenshot winsta handle leak/UAF (CRITICAL-13).** Eliminated
  `static mut CAPTURE_WINSTA_ORIGINAL/OPENED`; replaced with a
  `WinstaGuard { original, opened }` struct passed by value through
  `attach_interactive` → `detach_interactive`. The borrowed
  `GetProcessWindowStation` pseudo-handle is never closed; only the
  `OpenWindowStationW` handle is.
- **Slack/MCP/LLM C2 frame injection HMAC (CRITICAL-22/23/24).** All three
  relay transports now seal frames with `[HMAC-SHA256(32) ||
  len_be(4) || frame]` before encoding (base64 for Slack, hex for
  MCP/LLM). `open_frame` verifies the tag (constant-time via
  `hmac::Mac::verify_slice`) before returning bytes. Per-channel key
  derivation prevents cross-channel replay. Removed `xor_frame` entirely
  from LLM transport (the protocol AEAD provides confidentiality). 19 new
  frame-integrity tests.
- **sRDI export-table OOB (CRITICAL-25/26/27).** Every PE-derived slice
  index now bounds-checked via `checked_slice` helper. `num_names` capped
  at `1<<20`; `ordinal < num_names` enforced; `rva_to_off` takes a
  `max_read` parameter. All `as u32` size casts go through
  `usize_to_u32()` (errors on truncation). Malformed PE → descriptive
  `Err`, not panic.
- **EnableDebug.cs `cmd /c` argument injection (CRITICAL-28).** Removed
  the `cmd.exe /c` shim entirely; `args[0]` passed directly as
  `FileName`. Remaining args quoted via `WindowsArgvQuote()` (MSVC CRT
  rules). Deleted unused `CreateProcessAsUser` P/Invokes. SeDebugPrivilege
  behavior preserved.

### Known Limitations (deferred to v0.4.0)

- **CRITICAL-19 — beacon task isolation.** A single panicking task still
  aborts the beacon (architectural; requires spawn-to-sacrificial redesign
  for BOF/Inject).
- **Selftest gate TIMEOUT in CI.** Pre-existing since v0.3.0 — rundll32
  hangs in the non-interactive Session 0 of the win-17763 runner. All
  build steps pass; only the selftest execution gate times out. Requires
  remote debugging on the runner to diagnose.

## [0.3.1] - 2026-07-21

Security-and-correctness fix release following the 2026-07-21 full-codebase
audit (`docs/audits/FULL_CODE_AUDIT_2026-07-21.md`, 12 parallel sub-agents,
~78,849 LOC reviewed). This release closes the audit's top P0 findings — the
ones that would crash the beacon on first use, leave the injection path
non-functional, ship an open team server, or silently defeat the kill-date
safety control. The remaining CRITICAL/HIGH findings (crypto `.expect()`
refactors, `static mut` modernization, `blind_hwbp` rewrite, BOF/C2 HMAC
framing) are tracked for v0.3.2 and are **not** blockers for authorized
engagements — see Known Limitations.

### Fixed

- **fluctuation_thunk Win64 ABI stack alignment (CRITICAL).** Steps 1-3 of
  the sleep-mask thunk emitted `sub rsp, 0x20` / `add rsp, 0x20`, leaving
  RSP ≡ 8 (mod 16) at the `call` — any callee `movaps`/`movdqa` raised #GP/#PF,
  killing the beacon on the first sleep with `.text` still PAGE_NOACCESS and
  registered data regions still RC4-masked. Step 4 already used the correct
  `0x28` immediate; Steps 1-3 now match. `crates/implant-win/src/fluctuation_thunk.rs:126-211`.
- **NtHeapAllocator dealloc UAF on aligned pointers (CRITICAL).** The
  `align > 8` branch conditionally stored the raw pointer at
  `aligned_addr - 8` only when `offset >= 8`, but dealloc unconditionally
  read that slot. When `RtlAllocateHeap` returned an already-aligned block
  (common for align=16 under LFH), `offset = 0` → the store was skipped →
  dealloc freed a garbage address → heap metadata corruption. Now over-
  allocates `size + align + 8` and stores unconditionally. Also: the two
  `Layout::from_size_align(...).unwrap()` calls in `realloc` (panic=abort
  hazards on attacker-controlled sizes) now fail soft. `crates/implant-win/src/ntalloc.rs:258-330, 334-376`.
- **threadless_inject execute-breakpoint crash (CRITICAL).** The function
  set DR0=sc_addr + DR7=0x1 (local execute breakpoint) with RIP=sc_addr. An
  x64 execute breakpoint traps BEFORE the instruction at DR0 runs — with
  DR0 == RIP the first instruction raised #DB, and with no VEH registered
  the OS terminated the target on every call. The RIP hijack alone is
  sufficient and correct; the DR0/DR7 writes are removed. Also:
  `nt_suspend_thread` return value is now checked (was silently dropped —
  proceeding to NtGetContextThread/NtSetContextThread on a live thread
  raced). `crates/implant-win/src/inject.rs:652-746`.
- **inject_existing `CreateRemoteThread` NULL lpStartAddress (CRITICAL).**
  The primary existing-process inject path passed `None` as the start
  address and the shellcode address as `lpParameter` — the kernel rejects a
  NULL start address, so the call always returned NULL and the path was
  100% broken (operators always saw "CreateRemoteThread failed"). Now wraps
  the shellcode address in `Some(transmute(...))`, mirroring the working
  `remote_load_library` pattern. `crates/implant-win/src/inject.rs:1014-1024`.
- **stomp_and_resume cross-process buffer overrun (CRITICAL).**
  `WriteProcessMemory` wrote `shellcode.len()` bytes unconditionally into a
  region capped at `min(vsize, 0x2000)`. Any shellcode >8 KiB overran into
  the cover DLL's `.rdata`/`.data`, crashing the sacrificial process. Now
  bounds-checked; the RWX→RX restore (Step 5) also propagates errors
  instead of leaving `.text` RWX. `crates/implant-win/src/inject.rs:215-219`.
- **Kill-date never enforced (CRITICAL).** `ImplantConfig.expires_at` was
  decoded from the config blob (u64 unix seconds, 0 = no expiry) but
  `beacon_loop` never checked it — the implant ran forever, defeating the
  operator's engagement time-box safety control. Added
  `hostinfo::now_unix()` (resolves `GetSystemTimeAsFileTime` via PEB walk,
  converts FILETIME → unix seconds) and a per-cycle comparison at the top
  of `beacon_loop` that returns cleanly on expiry. A clock-resolution
  failure (`now_unix() == 0`) does NOT enforce, so a missing clock can't
  kill the beacon spuriously. `crates/implant-win/src/beacon.rs:187-196`,
  `crates/implant-win/src/hostinfo.rs:107-141`.
- **deaddrop JSON OOB panic (CRITICAL).** `json_extract_str` had two OOB
  bugs: `i += 1` past `:` ran unconditionally even when the preceding
  while-loop had exhausted the input, and `i < json.len() && json[i] == b' '
  || json[i] == b'"'` evaluated the right operand even when `i >= json.len()`
  (operator precedence). Under panic=abort any truncated GitHub response
  (network blip, 401/403 body) killed the implant. Both fixed.
  `crates/implant-win/src/trex/exfil/deaddrop.rs:113-138`.
- **selftests screenshot diag heap overflow (CRITICAL).**
  `nyx_selftest_screenshot_diag` computed `need = w*h*4` but allocated only
  `need.min(1<<20)` (1 MiB) — `GetDIBits` wrote `need` bytes, overrunning
  NT-heap metadata on any display larger than ~512×512. The export is
  compiled out of production DLLs (default no-selftest profile) but crashed
  dev/selftest builds. Now allocates the full `need`; `iLines` capped
  defensively. `crates/implant-win/src/selftests.rs:347-378`.
- **`is_loopback_bind` string-prefix bypass (HIGH).** The auto-token guard
  keyed off `starts_with("127.") / "localhost" / "::1"`, which missed
  `localhost.localdomain`, `0.0.0.0`, `[::]`, and bare `::1:8443` (whose
  `::1` literal parses as `1`, not loopback). A misconfigured `NYX_BIND`
  could ship an OPEN team server. Now parses the host out of the `host:port`
  string and delegates to `IpAddr::is_loopback` (authoritative for the full
  `127.0.0.0/8` range and `::1`). Unparseable input → fail-closed.
  `crates/server/src/lib.rs:998-1041`. New test
  `is_loopback_bind_closes_v030_string_prefix_bypasses` covers the bypass
  cases.
- **Kernel handlers executed with zero audit trail (HIGH).** All 6
  privileged kernel handlers (`dump_lsass`, `hide`, `blind_etw`,
  `neutralize`, `detach_minifilter`, `driver_status`) called `gate()` for
  admin RBAC but discarded the `OperatorIdentity` — the most sensitive
  operator actions (LSASS dump, process hiding, ETW blinding) left no audit
  record, defeating the audit log's "who tasked WHAT" contract. Each
  handler now captures `op` and writes an audit record before dispatching
  to the daemon, mirroring the `post_task` / `cred_add` pattern.
  `crates/server/src/kernel.rs:114-226`.
- **`implant_gen` expires ISO 8601 silent drop (HIGH).** The kill-date
  parser used `s.parse::<i64>().ok().map(...).unwrap_or(0)`, which only
  succeeded on bare integers — every ISO 8601 string (the documented input
  form; client placeholder is `"2026-12-31"`) failed and defaulted to 0
  ("never expire"). Operators believed they set a 30-day kill-date; the
  implant ran forever, and the audit record showed the intended date while
  the binary got 0. New `parse_iso8601_to_unix` accepts bare seconds,
  `YYYY-MM-DD`, and `YYYY-MM-DDTHH:MM:SS[Z|+00:00]`; parse failure now
  returns 400 (fail-closed). 4 new unit tests. Paired with the beacon-side
  kill-date enforcement above, operator kill-dates now actually fire.
  `crates/server/src/implant_gen.rs:233-340, 456-475`.

### Operational Notes

- **`do_inject` PID guard.** The operator-facing inject entry now rejects
  `pid == 4` (System kernel process — OpenProcess writes would BSOD) and
  `pid == self_pid` (self-inject, almost always a typo). `pid == 0` (the
  "spawn fresh sacrificial" sentinel) is still allowed.
  `crates/implant-win/src/inject.rs:800-820`.

### Known Limitations (deferred to v0.3.2)

The 2026-07-21 audit surfaced 27 CRITICAL + 46 HIGH findings across the
codebase. v0.3.1 closes the 10 that block first-use or ship an open server.
The remaining findings are real but are **not** blockers for authorized
engagements — they are tracked for v0.3.2:

- **panic=abort + `.unwrap()`/`.expect()`/`assert!`/`unreachable!()`** across
  ~30 sites (crypto `seal`/`decrypt`, protocol framing, BOF entry lookup).
  Requires Result-type refactors.
- **`static mut` global state** under the aliasing model (blind_hwbp, mem,
  screenshot, transport, keylog). Requires AtomicPtr/Mutex rewrites.
- **`blind_hwbp` VEH lock contention** returning EXCEPTION_CONTINUE_SEARCH
  (process kill). Requires a lock-free handler redesign.
- **Slack / MCP / LLM C2 frame injection** via unauthenticated channel
  messages and `extract_hex` longest-run heuristic. Requires HMAC framing.
- **sRDI export-table OOB reads** (tools/srdi). Outside the release matrix.
- **beacon task isolation** (single panicking task kills the beacon).
  Architectural — requires spawn-to-sacrificial for BOF/Inject.

Full detail in `docs/audits/FULL_CODE_AUDIT_2026-07-21.md`.

## [0.3.0] - 2026-07-21

First release with compiled Windows payloads + a real reflective PIC loader.
Establishes a tag-triggered release pipeline on the existing self-hosted
win-17763 runner and backfills the reflective loader that was previously
"intentionally out of scope". The release is published as a **GitHub Draft
Release** (assets not publicly listed) pending operator review.

### Added

- **Reflective PIC loader (`crates/nyx-loader`).** `generate_loader_stub()`
  was a `_config`-ignored stub; it now emits Layer-1 (call/pop self-location
  + NYX2 magic scan + header parse) + Layer-2 (PEB walk, RWX alloc, inline
  ChaCha20-Poly1305 decrypt with tag check, reflective PE load, DllMain call).
  The magic self-match scanner bug — the naive `cmp dword [rcx], 0x3258594E`
  matches its own operand inside the stub — is fixed via XOR recovery
  (`on_target::MAGIC_XOR_KEY = 0x5A5A5A5A`). 54 tests (lib 41 + integration
  13) cover byte layout, scan algorithm, payload format, and crypto
  roundtrip against the `chacha20poly1305` crate (`8a385cc`).
- **`crates/nyx-loader/examples/wrap.rs`** — CLI that wraps a PE DLL into
  a self-contained NYX2 blob with a random per-build key (`8a385cc`).
- **`tools/loader_probe_dll/`** — standalone Windows cdylib harness that
  `VirtualAlloc(RWX)` + `memcpy` + VEH-protected jump into a wrapped blob.
  Result file (`NYX_PROBE_RESULT` env or `C:\nyx\loader_probe_result.txt`):
  `OK rv=0x<HEX>` / `FAIL stage=<stage> [code=0x<HEX> addr=0x<HEX>]`
  (`8a385cc`, path fix `2222f08`).
- **`scripts/setup_release_env.ps1` + `docs/RELEASE_ENV.md`** — idempotent
  VPS setup: `MAPSReporting=0` + `SubmitSamplesConsent=2` (do not feed MS
  threat intel) + ExclusionPath for both the manual `C:\nyx` worktree and
  the CI checkout at `C:\actions-runner\_work\NY\NY` (`8a385cc`,
  `2222f08`).
- **`scripts/loader_probe.ps1`** — driver that builds the harness, spawns
  `rundll32`, polls for result file, parses OK/FAIL (`8a385cc`).
- **`scripts/release/*.ps1` (11 scripts)** — per-step build, gate, stage,
  notes-extraction (`8a385cc`).
- **`.github/workflows/release.yml`** — tag push → single-job sequential
  pipeline → `softprops/action-gh-release@v2` **draft** release
  (`8a385cc`).

### Security

- **Implant endpoint auth bypass (CRITICAL, inherited from unreleased).**
  `GET /api/implants` and `POST /api/implant/revoke` had zero
  authentication — any reachable client could enumerate all active implant
  metadata (callback hosts, ports, public keys) and arbitrarily revoke
  them, severing C2 connections. Both endpoints now require operator
  authentication and deny the anonymous Viewer fallback.
  `revoke_implant` audit attribution corrected from hardcoded `"system"` to
  the authenticated operator's name (fixes PR #44, `73006cd`).

### Operational Notes

- **Build environment transparency.** Built on the self-hosted Windows
  Server 2019 (build 17763) with Defender Realtime **ON**. Defender
  `ExclusionPath` is active for build dirs; `MAPSReporting` is disabled.
  DLLs are **unsigned**. See `docs/RELEASE_ENV.md` for reproducible setup.
- **Loader probe is release-blocking.** The reflective blob must inject +
  execute `DllMain` cleanly in the harness process before any draft
  release is created. A crash produces a `FAIL stage=invoke code=0x<N>`
  line in the result file; iteration is expected here.
- **Scope boundaries preserved.** Sleep obfuscation `fluctuation` is still
  not wired; 6 Transport channels still have zero consumers; BOF compat
  surface is still narrow. These known limits are inherited from v0.2.0
  and called out in release notes.

## [0.2.0] - 2026-07-21

First official release. The changelog aggregates the post-internal development window:
P0 memory-safety / protocol / RBAC hardening, the third real-hardware verification pass,
Foliage → Fluctuation sleep-mask migration, ExtC2 relay wiring, and the 2026-07-21
implant-win CI + DLL-surface + screenshot DPI + upload/beacon-reliability fixes.

### Added

- **Screenshot capture rebuilt on `CreateDIBSection`** with DPI-independent physical-pixel
  sizing, replacing the `CreateCompatibleBitmap` path that cropped to logical pixels
  (`23c01b0`). See Fixed for the crop bug this closes.
- **`beacon::encode_batch`** — graceful handling of oversized operator responses. Instead
  of the implant dying on an oversized blob, the batch is downgraded to an operator-visible
  error response (`1320b25`, P0-4).
- **ExtC2 relay, server side** — `extc2_relay` wiring that was previously only specified
  on the implant side. Slack and MCP channels now actually forward through the team server
  (#3 closed; `0945f79`).
- **`trex` WMI registry assessment** — the G1 TODO from the 12-TODO sweep; registry-based
  host assessment via WMI is now wired (`69b12fd` G1, `431e26d` #5).
- **Caller-spoof macro** — macro form of the existing caller-spoof scanner, wired into the
  evasion gate (`431e26d` #6).
- **Fluctuation sleep mask** — sleep obfuscation is no longer short-circuited in
  `kits::sleep`; the Fluctuation path is the live arm (`fffcf31`). This supersedes the
  Foliage APC chain (see Removed).

### Changed

- **CI now actually runs `--features selftest`** and gates PRs on sentinel presence and
  non-zero exit codes. Previously the gate was a no-op (the selftest binary was compiled
  but not executed and its exit code was not inspected) (`88c1fb2`, P0-5). Ghost references
  from the CI script were removed in the same commit.
- **Production DLL export surface reduced to 4 exports**: `DllMain`, `nyx_entry`,
  `nyx_entry_noevasion`, `nyx_screenshot_session`. The 7 `nyx_selftest_*` exports and
  `nyx_screenshot_test` are now compiled out by default behind a `cfg` gate and only
  emitted under the `selftest` feature (`2f20e0a`, P0-6).
- **Screenshot temp file renamed `nyx_shot.bmp` → `~dfftmp.bmp`** for IOC hygiene
  (`23c01b0`). The previous name was a stable, brandable indicator.
- **`do_upload` now loops in `CHUNK`-sized blocks, advancing the file cursor by the actual
  bytes written** rather than assuming a full `CHUNK` per write (`87f9e51`, P0-2). See
  Fixed for the truncation bug this closes.

### Fixed

- **P0-1 — `ntalloc` slab table data race.** The slab free-list was mutated from multiple
  threads without synchronization. Converted to atomic operations (`341e8a2`).
- **P0-2 — `do_upload` silent short-write truncation.** A partial write advanced the cursor
  by `CHUNK` anyway, silently truncating the exfil file. Now advances by actual bytes
  written and re-issues the remainder (`87f9e51`).
- **P0-3 — beacon sequence-number burn on send failure.** A failed transport send still
  incremented the sequence counter, burning task IDs the operator would never see
  acknowledged. The batch is now retained for retry on send failure (`1320b25`).
- **P0-4 — `encode_vec.expect()` panic on oversized blobs.** An operator response that
  exceeded the protocol frame limit panicked the beacon. Replaced with `encode_batch`,
  which downgrades to an error response (see Added) instead of killing the implant
  (`1320b25`).
- **Screenshot DPI crop at >100% scaling.** Under RDP at 200% DPI, capture returned
  1147×719 instead of the physical 2294×1438. Root cause was `CreateCompatibleBitmap`
  inheriting the logical DPI of the screen DC. Fixed by switching to `CreateDIBSection`
  with an explicit physical-pixel BITMAPINFO (`23c01b0`, `ad50625` "DPI 虚拟化").
- **Hive `allowed()` leading-slash path traversal bypass.** A path beginning with `/`
  bypassed the allowlist check. Closed in PR #41 (`c9a3593`).
- **COFF relocation off-by-one** in the BOF loader's REL32 emitter (`ad50625`).
- **x64 injection base address** miscalculation in the third real-hardware pass
  (`ad50625`).
- **P0 — RBAC bypass / nonce race / argon2id upgrade.** Server hardening pass: RBAC role
  check was bypassable on a class of routes; the per-session nonce counter had a TOCTOU
  race; password hashing upgraded to argon2id (`ed0af87`).
- **P0 — RWX memory leak + `%s` out-of-bounds read** in the BOF runner. RWX pages were
  leaked across BOF invocations; a `%s` format specifier read past the argument buffer on
  non-null-terminated inputs (`548c5be`).
- **P0 — protocol blob cap / `REL32_N` / `ADDR32NB`** sanity bounds in the protocol and
  COFF layers, plus corrected `.expect()` messages (`265e140`).
- **Second-round soundness pass** across `nyx-mutate` / `bof` / `coff` / `loader`
  (`8e7f507`).
- **Server-side audit hardening, round 2** — DoS limits, `created_by` attribution, rate
  limiting, clock skew handling (`e0c342b`).
- **Implant endpoint auth bypass (CRITICAL).** `GET /api/implants` and
  `POST /api/implant/revoke` had no authentication. Now require operator
  auth and block anonymous Viewer access (PR #44).

### Removed

- **Foliage APC chain**, superseded by Fluctuation (see Added). The `sleep.rs` Foliage
  scaffolding was dead code flagged 🔴 in the 2026-07-18 audit (`13c0064`, `74c9663`,
  `fffcf31`).
- **2 dead selftest helpers** that compiled but were never invoked by any sentinel
  (`13c0064`).
- **`FoliageRaw` dead fields** — 5 of 6 struct fields were never read; the struct is gone
  with the Foliage path (`13c0064`).
- **`MAX_ROTATION_HOSTS` dead const** — declared, never referenced (`13c0064`).
- **Features that could not be verified on real hardware**, replaced with implementable
  techniques (`74c9663`): Layer 2 reflective load, CET `IRET_FRAME`, multi-monitor
  screenshot selection. See Known Limitations for the test-coverage gap that drove these
  removals.

### Security

This release closes the P0 hardening backlog surfaced by the 2026-07-18 code-truth audit.
Operators rebuilding from source should treat all of the following as reasons to rotate
any beacon built from a pre-`0.2.0` tree:

- **RBAC bypass** — a class of team-server routes skipped the role check (`ed0af87`).
- **Nonce race** — per-session replay counter had a TOCTOU window (`ed0af87`).
- **argon2id upgrade** — operator password hashing moved to argon2id; legacy hashes must be
  re-issued (`ed0af87`).
- **RWX memory leak** in the BOF runner — pages persisted across BOF calls, expanding the
  detectable RWX footprint (`548c5be`).
- **`%s` out-of-bounds read** in BOF argument formatting — read past the argument buffer
  on inputs lacking a terminator (`548c5be`).
- **Protocol blob DoS** — unbounded blob size on ingress; now capped (`265e140`).
- **Hive path traversal** — leading-slash bypass of `allowed()` (PR #41, `c9a3593`).
- **Implant endpoint auth bypass (CRITICAL).** `GET /api/implants` and
  `POST /api/implant/revoke` were completely unauthenticated — any reachable
  client could enumerate all active implant metadata and arbitrarily revoke
  implants, severing C2 connections. Both endpoints now require operator
  authentication and deny the anonymous Viewer fallback (PR #44).

### Known Limitations

Honest scope for this release. None are blockers for authorized engagements, but each
narrows what `0.2.0` can be claimed to do.

- **CI runner coverage is single-host.** The self-hosted runner is Windows build 17763
  (Server 2019). Hosted-runner coverage on Windows 11 24H2 is blocked by billing and is
  not running.
- **No end-to-end beacon↔server round-trip test for the PIC implant.** The only implant
  shape that is round-tripped in CI is `agent-dev`. The production `implant-win` PIC DLL
  has selftest exports but no automated full-loop test.
- **`agent-dev` and `implant-win` are a divergent parallel reimplementation.** There is no
  shared trait enforcing response-shape parity between the dev harness and the production
  implant, so a fix in one does not automatically propagate to the other.
- **200% DPI screenshot fix is verified only on Windows Server 2019 RDP**, not yet on
  Windows 11. The `CreateDIBSection` path is expected to behave identically but has not
  been confirmed on Win11 hardware.
- **No ARM64 build.** x64 only.

[Unreleased]: https://github.com/qiaozhiyi/NY/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/qiaozhiyi/NY/releases/tag/v0.2.0
