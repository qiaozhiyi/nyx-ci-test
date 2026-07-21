# Changelog

All notable changes to the Nyx C2 framework are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0` is treated as a pre-release internal state that was never officially tagged;
`0.2.0` is the first shipped release. Entries cite the originating commit short-SHA so
operators can `git show` the exact change. Evidence is authoritative over prose — when
this file and the code disagree, the code wins.

## [Unreleased]

_Nothing staged._

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
