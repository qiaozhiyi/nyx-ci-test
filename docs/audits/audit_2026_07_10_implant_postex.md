# Implant post-exploitation & T-REX subsystem — deep audit (2026-07-10)

**Scope:** `crates/implant-win/src/` — `bof.rs`, `hashdump.rs`, `postex.rs`,
`fs.rs`, `pivot.rs`, `keylog.rs`, `screenshot.rs`, `selftests.rs`, `recon.rs`,
`envprobe.rs`, `envelopes.rs`, `heap.rs`, `insomniac.rs`, `kits.rs`, and
`trex/` (`mod.rs`, `cleanup.rs`, `delivery.rs`, `melt.rs`, `exfil/mod.rs`,
`exfil/deaddrop.rs`).
**Method:** line-by-line static review; every claim cites lines actually
observed. `git diff` run on every domain file; the three fix-in-progress files
(`bof.rs` +16, `selftests.rs` +62, `trex/mod.rs` +25) audited as new code.
**Authorization:** internal red-team C2 improvement — no weaponizable payloads.

---

## 0. Summary of the three in-progress fixes

| Fix | File | Verdict |
|-----|------|---------|
| HIGH-NEW-BOF1 (BeaconDataExtract i32 overflow) | `bof.rs` | **FIXED (sound)** — with one residual nit (unaligned read). |
| HIGH-NEW-BOF2 (~40 selftest exports in prod) | `selftests.rs` + `Cargo.toml` | **PARTIALLY FIXED** — 50/51 exports gated; `nyx_selftest_trex` in `trex/mod.rs:900` and `noop_veh_handler` in `selftests.rs:2803` MISSED. |
| CRIT-3 (T-REX always returns Clean) | `trex/mod.rs` | **FIXED (sound)** — honest `Unknown` + banner on both the selftest and the operator-facing beacon path. |

The fixes are examined in detail in §1 (per-finding re-verification) and
critiqued as new code in §3.

---

## 1. Re-verification of the 2026-07-08 baseline

| Prior ID | Finding | Prior lines | Current status |
|----------|---------|-------------|----------------|
| CRIT-3 | T-REX recon all stubs → Clean | `trex/mod.rs:779-847` | **FIXED** (honest Unknown banner; see §3.1) |
| HIGH-NEW-BOF1 | BeaconDataExtract i32 overflow → OOB | `bof.rs:368-376` | **FIXED** (checked_add; see §3.2) |
| HIGH-NEW-BOF2 | ~40 selftest exports in prod | `selftests.rs` | **PARTIALLY FIXED** (2 exports missed; see §3.3) |
| HIGH-NEW-BOF3 | hashdump_diag hangs beacon | `selftests.rs:717-724` | **FIXED** (export now feature-gated; see note) |
| HIGH-6 | deaddrop 16 KiB truncation | `deaddrop.rs:140-141` | **STILL PRESENT** (`deaddrop.rs:140`) |
| HIGH-7 | melt no arming guard | `melt.rs:133-144` | **STILL PRESENT** (`melt.rs:133-144`) |
| MED-NEW-BOF4 | alloc_near REL32 window too small | `bof.rs:616-645` | **STILL PRESENT** (`bof.rs:628-648`) |
| MED-NEW-BOF5 | save_hive writes to Temp w/ NULL SA | `hashdump.rs:671-674` | **STILL PRESENT** (`hashdump.rs:694, 720`) |
| MED-NEW-BOF6 | joined buffer + make_token pwd not zeroized | `hashdump.rs:206`, `postex.rs:339` | **STILL PRESENT** (`hashdump.rs:206`, `postex.rs:341`) |
| MED-NEW-BOF7 | fileop_cp loads whole file → OOM | `fs.rs:789-843` | **STILL PRESENT** (`fs.rs:789`) |
| MED-NEW-BOF8 | fileop_mv dest truncation at 260 | `fs.rs:747-751` | **STILL PRESENT** (`fs.rs:749-751`) |
| MED-NEW-BOF9 | SOCKS5 BIND peer reuse | `pivot.rs:597-614` | **STILL PRESENT** (`pivot.rs:597-614`) |
| MED-NEW-BOF10 | wipe_prefetch panic on long name | `trex/cleanup.rs:115-142` | **STILL PRESENT** (`trex/cleanup.rs:132`) |
| LOW-8 | msmpeng misclassified + dead branch | `trex/mod.rs:711, 718` | **STILL PRESENT** (latent; mitigated by CRIT-3 Unknown) |
| LOW-9 | delivery APC non-alertable thread | `trex/delivery.rs:246` | **STILL PRESENT** (`trex/delivery.rs:202-214`) |
| NEW-11 | keylog Relaxed load post-dump | `keylog.rs:593` | **STILL PRESENT** (`keylog.rs:593`) |

### [HIGH] HIGH-6 — deaddrop 16 KiB payload truncation (STILL PRESENT)
- **位置:** `trex/exfil/deaddrop.rs:140-141` (payload), `:204` (gist_id), `:191` (response)
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  let mut b64_buf = [0u8; 16384];                        // :140
  let b64_len = base64_encode(encrypted_payload, &mut b64_buf); // :141
  ```
  `base64_encode` (`:93`) silently stops writing once `wi + 4 > output.len()` —
  no error on overflow, just truncation. Body assembled from `&b64_buf[..b64_len]`
  (`:148`). Additionally a **new truncation point**: the gist-ID extraction buffer
  is `let mut gist_id = [0u8; 32];` (`:204`) and `json_extract_str` (`:115`)
  writes with `o + 1 < out.len()` → caps at 31 chars + NUL. A GitHub gist ID is
  exactly 32 hex chars in the classic format, so the ID is truncated to 31 chars
  and the C2 retrieves the wrong/missing gist.
- **影响:** Silent data loss in the exfil path (truncated report); with the
  gist-id bug, the C2 cannot retrieve the gist at all (wrong ID) — total
  dead-drop failure for classic-format IDs.
- **修复:** Grow `b64_buf` dynamically (heap::Vec is available — `body` already
  is one) and return `Err` from `base64_encode` on overflow. Enlarge
  `gist_id` to `[u8; 64]` and/or have `json_extract_str` return a length so the
  caller can detect truncation.

### [HIGH] HIGH-7 — melt::self_destruct has no arming guard (STILL PRESENT)
- **位置:** `trex/melt.rs:133-144`
- **状态:** STILL PRESENT (latent — still zero callers in `src/`)
- **已核验:** `self_destruct` performs the 5-step wipe unconditionally; no
  `ARMED`/`AtomicBool` gate. `wipe_and_free_pages` (:65-83) still RX→RW→zero→free
  whatever pointer it is handed with no validation. Still `pub` and exports-ready.
- **影响:** Permanent implant death from any accidental reach (panic handler,
  mis-wired command).
- **修复:** Require an `armed: &AtomicBool` the operator sets via a two-step
  `Melt { arm }` command; validate `rx_pages`/`module_base` against the known
  image range before wiping.

### [MEDIUM] MED-NEW-BOF4 — alloc_near only probes 64 MiB of 2 GiB REL32 window (STILL PRESENT)
- **位置:** `bof.rs:628-648`
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  const STEP: usize = 1 << 20; const WINDOW: usize = (2u64 << 30) as usize; // :630-631
  while hint > floor && tries < 64 { … hint = hint.saturating_sub(STEP); tries += 1; } // :636-647
  ```
  Still 64 × 1 MiB = 64 MiB probe budget, then NULL-hint fallback at :651 with
  the comment "REL32 may overflow."
- **影响:** Under ASLR/crowded AS the near probe fails; BOF mapped far from the
  image; REL32 displacement overflows → call to garbage → segfault (implant death).
- **修复:** Raise the budget to `WINDOW / STEP` (2048) or `VirtualQuery`-scan for
  a free gap before allocating.

### [MEDIUM] MED-NEW-BOF5 — hashdump save_hive writes SAM hive with NULL SA (STILL PRESENT)
- **位置:** `hashdump.rs:694` (primary `save` call), `:720` (alt-name fallback)
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  rc = unsafe { save(hkey, alt_wide.as_ptr(), core::ptr::null()) }; // :720 — NULL SA
  ```
  Both `RegSaveKeyW` invocations pass `core::ptr::null()` for
  `lpSecurityAttributes` → default ACL on `C:\Windows\Temp\*.hive`. `delete_temp`
  (`:766`) only runs on the happy path (`:93`). The alt-name fallback (`:709-729`)
  writes a second `.hive` and only cleans the *original* stale file (`:724-726`),
  not necessarily itself on a later failure.
- **影响:** Credential material (NTLM-hash-bearing hive bytes) materialized on
  disk under the default Temp ACL if the beacon dies mid-stream.
- **修复:** Create the temp file with an owner-only NULL-DACL `SECURITY_ATTRIBUTES`;
  `secure_zero` the streamed bytes; register the temp path with `melt` for exit
  cleanup; ensure the alt-name path also self-deletes on failure.

### [MEDIUM] MED-NEW-BOF6 — joined buffer + make_token password never zeroized (STILL PRESENT)
- **位置:** `hashdump.rs:206` (`joined`), `postex.rs:341` (`wpass`)
- **状态:** STILL PRESENT
- **已核验:** `do_hashdump` joins all hive chunks into `joined: Vec<u8>` (`:206`)
  and returns it as `Response::Output(joined)` (`:216`) — never zeroed. The bump
  allocator never frees, so the SAM/SYSTEM bytes sit in committed memory for the
  process lifetime. `make_token` widens the password into `wpass: [u16; 256]`
  (`:341`) and the function ends at `:398` with `wpass`/`wuser`/`wdom` still on
  the stack, never overwritten.
- **影响:** Credential material recoverable from a memory capture (Volatility /
  procdump + strings).
- **修复:** After the response is built, `melt::secure_zero` the chunk Vecs +
  `joined`; `secure_zero(&mut wpass)` (and `wuser`/`wdom`) at the end of
  `make_token` on every return path.

### [MEDIUM] MED-NEW-BOF7 — fileop_cp loads whole file into Vec → OOM (STILL PRESENT)
- **位置:** `fs.rs:789`
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  let src_chunks: Vec<Vec<u8>> = unsafe { … loop { … out.push(buf[..got].to_vec()); } … };
  ```
  Still buffers the entire source into a `Vec<Vec<u8>>` before writing the dest.
  The comment at `:786-788` still acknowledges the OOM risk.
- **影响:** `cp` of a multi-GB VHD/pagefile/database OOMs the implant
  (`panic=abort` → implant death).
- **修复:** Stream: open src + dest, read one CHUNK, write one CHUNK, repeat.

### [MEDIUM] MED-NEW-BOF8 — fileop_mv silently truncates destination to 260 wchar (STILL PRESENT)
- **位置:** `fs.rs:749-751`
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  let dn = destbuf.len().min(info.file_name.len());   // file_name is [u16; 260]
  info.file_name[..dn].copy_from_slice(&destbuf[..dn]);
  info.file_name_length = (dn * 2) as u32;
  ```
  `dn` still caps at 260 and the rename targets a truncated path silently. The
  variable-length `info_len = 20 + file_name_length` (`:760`) already supports
  longer names but the fixed `[u16; 260]` field in `FileRenameInformation` caps it.
- **影响:** Silent wrong-target rename on long paths; operator told `Ok`.
- **修复:** Return `Err` when `destbuf.len() > 260`, or allocate
  `FileRenameInformation` with a variable-length trailing `file_name`.

### [MEDIUM] MED-NEW-BOF9 — SOCKS5 BIND peer reuse + listener never auto-closes (STILL PRESENT)
- **位置:** `pivot.rs:597-614`
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  if c.listening {
      let accepted = unsafe { try_accept(c.sock) };
      if let Some(peer) = accepted {
          if unsafe { add_channel_kind(c.chan, peer, false) } { … }   // :603 — reuses listener chan
      }
      i += 1; continue;
  }
  ```
  The accepted peer reuses the listener's `chan` id; the listener (`c.listening`
  never cleared) stays open and keeps accepting across cycles. `slot_of_active`
  (`:157`) returns the first non-listening match, so a second accepted peer with
  the same chan starves and its data is indistinguishable on the wire.
- **影响:** SOCKS5 BIND broken for >1 callback connection; data misroutes;
  listener lingers as a forensic footprint.
- **修复:** After the first accepted peer, close the listener
  (`closesocket` + `CHANNELS[i] = None`) and reject/renumber further accepts.

### [MEDIUM] MED-NEW-BOF10 — wipe_prefetch panics on >103-char unit name (STILL PRESENT)
- **位置:** `trex/cleanup.rs:132` (panic), `:134` (malformed UNICODE_STRING)
- **状态:** STILL PRESENT
- **已核验:**
  ```rust
  let mut path = [0u16; 128];
  let prefix: &[u16] = &[ …25 units… ];      // pl = 25
  path[..pl].copy_from_slice(prefix);
  path[pl..pl+name.len()].copy_from_slice(name);   // :132 — panics if pl+name.len() > 128
  let us = UnicodeStr { len: ((pl + name.len()) * 2) as u16, max: 256, … }; // :134 — max hardcoded
  ```
  No bounds check; `name` > 103 UTF-16 units → slice OOB → panic → `panic=abort`
  → implant death. `max: 256` is hardcoded regardless of actual buffer (128).
- **影响:** A long/mangled prefetch image name on the cleanup path kills the implant.
- **修复:** Bounds-check `pl + name.len() <= 128` and skip/Err on overflow;
  set `max = (pl + name.len()) * 2`.

### [LOW] LOW-8 — msmpeng misclassified as ATP + dead branch (STILL PRESENT, latent)
- **位置:** `trex/mod.rs:734` (msmpeng→ATP), `:742` (dead consumer branch)
- **状态:** STILL PRESENT (mitigated in practice by CRIT-3's Unknown early-return)
- **已核验:** `:734` still maps `msmpeng` → `MicrosoftDefenderATP`; `:742`
  `msmpeng && defender` → `Vendor::Defender` is still dead. `is_edr_driver`
  (`:796`) still flags `windefend`/`wdfilter` standalone.
- **影响:** Currently inert (the whole engine returns Unknown before reaching
  this code). When scanners are implemented, every consumer-Windows box would be
  tier-escalated to EnterpriseEDR/Fortress → over-evasive recommendation burned
  on a soft target.
- **修复:** Move `msmpeng` to the consumer `Vendor::Defender` branch; drop the
  dead `:742`; key ATP on `mssense`/Sense. Only treat `wdfilter`/`windefend` as
  EDR when paired with a `mssense`/Sense process hit.

### [LOW] LOW-9 — delivery APC queued to a non-alertable thread (STILL PRESENT)
- **位置:** `trex/delivery.rs:202-214` (`find_target_thread`), `:246` (`nt_queue_apc`)
- **状态:** STILL PRESENT
- **已核验:** `find_target_thread` (`:184`) opens the first thread owned by `pid`
  with `THREAD_SET_CONTEXT` and no alertability check; `section_jacking_inject`
  queues a user APC via `nt_queue_apc` (`:246`). User APCs only fire on an
  alertable wait.
- **影响:** Silent injection failure on a non-alertable thread; dangling RX view
  left in the target (detection surface).
- **修复:** Target an alertable thread, or use `NtQueueApcThreadEx` special-user-APC
  (Win11+), or fall back to `NtCreateThreadEx` on the remote view.

### [LOW] NEW-11 (07-08) — keylog Relaxed load post-dump (STILL PRESENT)
- **位置:** `keylog.rs:593` (writer load)
- **状态:** STILL PRESENT
- **已核验:** `buf_push_release` still does
  `let len = BUF_LEN.load(Relaxed)` (`:593`); the beacon's
  `BUF_LEN.store(0, Release)` (`:982`) pairs Release→Relaxed (not Acquire).
- **影响:** 1-2 keystrokes may be dropped immediately after each dump.
- **修复:** Load with `Acquire` in `buf_push_release`.

---

## 2. NEW findings (not in the 07-08 baseline)

### [HIGH] NEW-1 — COFF loader leaks every section allocation (no VirtualFree, ever)
- **位置:** `bof.rs:720-791` (alloc), `:803-815` (run, no cleanup)
- **状态:** NEW
- **已核验:** `run()` allocates one RW region per COFF section via `alloc_near`
  (`:725`), copies bytes, applies relocations, flips code→RX (`:776-791`), calls
  `go()` (`:812`), captures output, and returns `Response::BofOutput` (`:814`).
  A repo-wide grep for `VirtualFree`/`virtual_free`/`MEM_RELEASE`/`MEM_DECOMMIT`
  in `bof.rs` returns **zero matches**. `bases: Vec<u64>` (`:720`) is dropped at
  function exit but that only frees the Rust `Vec` of addresses — the underlying
  `VirtualAlloc` regions are never released.
- **描述:** Every BOF execution permanently leaks `(number_of_sections ×
  page-aligned section size)` bytes of committed RX/RW memory. Combined with the
  bump allocator note (HIGH-8 baseline: the implant heap never frees), this is
  unbounded growth on the one resource that cannot be reclaimed. A BOF with 4
  sections of 64 KiB leaks ~256 KiB per run; an operator loop executing a BOF
  every minute leaks ~36 MiB/hour. Worse, the RX pages containing the BOF's
  relocated `.text` are a prime forensic target (PE-sieve / Moneta scan for
  unmapped RX pages) and persist for the implant's lifetime.
- **影响:** (a) Eventual memory exhaustion → implant death on long sessions with
  repeated BOF use. (b) Each leaked RX section is a durable in-memory IOC that
  survives the BOF call and is trivially found by a memory scanner — directly
  contradicting the module's own W^X hygiene goal.
- **修复:** After `go()` returns and output is captured (`:813`), loop over
  `bases`/`sizes` and `VirtualFree(.., MEM_RELEASE)` each region (data sections
  first, then the now-stale code sections). Zero the pages before free. Wrap the
  whole `run()` body so an early `return Response::Err` on the alloc/reloc/protect
  paths also frees whatever was already allocated (a `defer`/RAII guard or a
  cleanup label).

### [MEDIUM] NEW-2 — `nyx_selftest_trex` and `noop_veh_handler` exports NOT feature-gated (fix gap)
- **位置:** `trex/mod.rs:900-901` (`nyx_selftest_trex`), `selftests.rs:2803-2806` (`noop_veh_handler`)
- **状态:** NEW (gap in the HIGH-NEW-BOF2 fix)
- **已核验:** The selftest feature-gating diff adds `#[cfg(feature = "selftest")]`
  above all 50 `nyx_selftest_*`/`nyx_linger*` exports in `selftests.rs`, but two
  `#[no_mangle]` exports escaped the patch:
  - `trex/mod.rs:900-901`:
    ```rust
    #[no_mangle]
    pub unsafe extern "system" fn nyx_selftest_trex() -> ! {
    ```
    This is the ONLY `#[no_mangle]` in the `trex/` subtree (verified:
    `grep -rn 'no_mangle' crates/implant-win/src/trex/` returns just this line).
    It ships in every production build, writes `C:\nyx\trex_report.txt`
    (`:931, :937`), and exit-codes the process (`:908`). Its name is a trivial
    YARA/signature target.
  - `selftests.rs:2803-2806`:
    ```rust
    #[no_mangle]
    pub unsafe extern "system" fn noop_veh_handler(_ep: usize) -> i32 { 0 }
    ```
    Not a selftest per se (it is a VEH stub the forwarder regression test
    registers), but it is a stable named export in the production PE table.
- **描述:** The fix plan's intent ("gate the ~50 exports behind
  `#[cfg(feature = "selftest")]`; production builds exclude all selftest
  exports" — `Cargo.toml` diff comment) is only ~96% realized. The two
  remaining exports keep a discoverable `nyx_`-prefixed / named entrypoint and
  (for `nyx_selftest_trex`) an on-disk `C:\nyx\` artifact in production. An
  analyst/EDR enumerating the export table still finds them.
- **影响:** Residual detection surface: the largest avoidable IOC the fix set
  out to remove is still partially present. `nyx_selftest_trex` is the more
  serious of the two (named `nyx_` export + disk artifact + process exit).
- **修复:** Add `#[cfg(feature = "selftest")]` above `trex/mod.rs:900` (and
  consider moving `write_report`/`nyx_selftest_trex` into `selftests.rs` so a
  single gating pass covers everything). Gate `noop_veh_handler` too, or
  rename it to a non-`nyx_`/non-descriptive symbol and document why it must ship.

### [MEDIUM] NEW-3 — BeaconPrintf format parser drops length modifiers → BOF arg desync + mangled output
- **位置:** `bof.rs:144-206` (`format_into`), spec match at `:160-203`
- **状态:** NEW
- **已核验:** After the `%`, `format_into` matches a single byte:
  ```rust
  match fmt[i] {
      b's' => { … ai += 1; }     // :161
      b'd' | b'i' => { … ai += 1; } // :174
      b'x' => { … ai += 1; }     // :183
      b'c' => { … ai += 1; }     // :192
      b'%' => out_push(b"%"),    // :198
      other => { out_push(&[b'%', other]); }  // :199 — NO ai advance
  }
  ```
  There is NO handling of `%p` (pointer), `%u`, or any length/width modifier
  (`%ld`, `%lu`, `%lld`, `%llx`, `%zu`, `%08x`, `%-16s`). `%p` and `%u` fall to
  the `other` arm and are emitted literally WITHOUT consuming an arg slot, but
  the C caller DID push a value — so the next specifier reads the wrong arg.
  Width modifiers (`%08x`) don't desync args (the digits are part of the format
  string, not an arg) but produce mangled output (`%0` literal + `8` + hex).
- **描述:** Real-world BOFs (including stock AggressorOperator/CS-community BOFs)
  routinely use `%s` with a `wchar_t*` cast via `%ls`, `%p` for pointer dumps,
  `%lu`/`%u` for `DWORD`, and `%llx`/`%lld` for 64-bit values. Any of these
  either desynchronizes the vararg cursor (wrong data for all subsequent args) or
  corrupts the output. The varargs are modeled as a fixed `[u64; 6]` (`:145`),
  so a desync cannot OOB-read the array (bounded by `ai < args.len()`), but the
  BOF's output is wrong and, for `%ls`, a `wchar_t*` printed via `%s` reads the
  wide string as ASCII (garbage). `%p` desync is the worst: it silently shifts
  every following argument.
- **影响:** BOFs using common printf features produce wrong output or crash
  (e.g. a `%s` after a skipped `%p` reads a pointer-typed arg as a string
  pointer → either garbage or AV inside `format_into`). Not a memory-safety bug
  in the implant itself (args array is bounded) but a correctness failure in a
  live path that makes BOF output unreliable.
- **修复:** Extend the parser to skip length modifiers (`l`, `ll`, `L`, `z`,
  `j`, `t`, `h`, `hh`) and a leading width/flag field before the conversion byte;
  add `%p` (consume one arg, print as `0x%08x`), `%u`/`%lu` (unsigned decimal),
  and treat `%ls` as a wide-string read. At minimum, when an unknown specifier
  is hit, also advance `ai` if the conversion is one known to consume an arg
  (`p`, `u`, `n`) so the cursor stays aligned.

### [MEDIUM] NEW-4 — deaddrop leaks PAT token + encrypted payload on the never-freed heap
- **位置:** `trex/exfil/deaddrop.rs:146-149` (`body`), `:168-173` (`auth`)
- **状态:** NEW
- **已核验:**
  ```rust
  let mut body = crate::heap::Vec::with_capacity(…);   // :146
  body.extend_from_slice(json_prefix);                 // :147
  body.extend_from_slice(&b64_buf[..b64_len]);         // :148
  body.extend_from_slice(json_suffix);                 // :149
  …
  let auth = { let mut s = to_utf16(b"Authorization: token "); … pat_token bytes … }; // :168-173
  ```
  `body` (containing the base64 of the encrypted recon report) and `auth`
  (containing the cleartext GitHub PAT, UTF-16) are both `crate::heap::Vec`
  dropped at function return — but the implant heap is the bump allocator that
  **never frees and never zeroes** (HIGH-8 baseline). So both the PAT and the
  encrypted payload persist in committed memory for the process lifetime,
  recoverable by a memory capture. The PAT is the more serious leak: it is a
  long-lived credential that grants read/write to the operator's GitHub gists.
- **影响:** GitHub PAT recoverable from a forensic memory image of the implant
  → operator attribution + gist tampering. The encrypted payload is lower-risk
  (already encrypted) but still an attribution correlate.
- **修复:** After `WinHttpSendRequest` + response read, `melt::secure_zero`
  both `body` and `auth` (and the `b64_buf`) before they drop. Better: route
  secret-bearing buffers through `crate::mem` registered-owned pages so
  `melt::self_destruct` wipes them on exit. Consider re-resolving the PAT at
  each call from an encrypted config blob rather than holding it.

### [MEDIUM] NEW-5 — `fs::allowed()` hive guard bypassable via `..` with an intermediate component
- **位置:** `fs.rs:162-217` (normalization), `:204-210` (blocked substrings)
- **状态:** NEW
- **已核验:** The normalization (`:186-196`) splits on `\` and drops empty and
  `.` segments, but does **NOT** collapse `..`. So a path like
  `C:\config\dummy\..\sam` normalizes to `\config\dummy\..\sam`, which the
  filesystem resolves to `C:\config\sam` — but the `clean` string does **not**
  contain the blocked substring `\config\sam` (it contains `\config\dummy` then
  `\..\sam`). The loop at `:211-215` therefore does not match, and `allowed()`
  returns `true`. (The prior audit said this guard was "not bypassable as
  written"; it is, via this pattern.) Any of the five blocked hives can be
  reached this way: `\config\dummy\..\system`, `\config\x\..\security`, etc.
- **描述:** The hive-protection guard exists specifically to stop an operator
  (or a chained command) from `download`/`rm`/`mv`/`cp`-ing a live hive, which
  would hang the beacon loop on the SAM oplock (see hashdump_diag, NEW-3 of
  07-08) or destroy credential material. The `..` bypass defeats it. Severity is
  bounded because the path is operator-controlled (not attacker-controlled) and
  the guard is a footgun-prevention safety net rather than a security boundary —
  but it is a false safety guarantee operators rely on, and a `download` of the
  SAM via this path bricks the beacon exactly as the selftest did.
- **影响:** Operator can hang/kill the beacon by downloading a live hive
  through a `..`-laced path the guard was supposed to refuse; can also
  `rm`/`mv` a hive.
- **修复:** Collapse `..` during normalization (when a `..` segment follows a
  non-`..` segment, drop both), or canonicalize the path via `RtlGetFullPathName_U`
  before the substring check. At minimum, reject any path containing a `..`
  segment outright for the protected operations.

### [LOW] NEW-6 — keylog dump read-reset race loses a keystroke written during snapshot
- **位置:** `keylog.rs:972-982` (dump path)
- **状态:** NEW (distinct mechanism from NEW-11)
- **已核验:**
  ```rust
  let len = BUF_LEN.load(Ordering::Acquire);   // :972
  … copy [0..len] into out …                    // :978-980
  BUF_LEN.store(0, Ordering::Release);          // :982
  ```
  Between the load (`:972`) and the store (`:982`), the hook thread can write a
  byte via `buf_push_release` (load `BUF_LEN` Relaxed at `:593`, write `BUF[len]`,
  store `len+1` Release at `:601`). The new byte lands at index `len` (outside the
  reader's `[0..len)` copy) and is then discarded by the `store(0)` at `:982`.
  This is the classic SPSC read-reset race without CAS.
- **影响:** A keystroke arriving in the exact window between snapshot-load and
  reset-store is permanently lost. Low-fidelity, not a crash.
- **修复:** Use a CAS-based claim (load `len`, copy, then
  `compare_exchange(len, 0)` — if it fails because the writer advanced, re-copy
  the delta) or a double-buffer.

### [LOW] NEW-7 — `insomniac::check_preservation` parses PE header with unvalidated `e_lfanew`
- **位置:** `insomniac.rs:40-44`
- **状态:** NEW
- **已核验:**
  ```rust
  let e_lfanew = unsafe { *(module_base.add(0x3C) as *const i32) } as usize; // :40
  let nt = unsafe { module_base.add(e_lfanew) };                              // :41
  let num_sec = unsafe { *(nt.add(6) as *const u16) } as usize;              // :42
  let opt_sz = unsafe { *(nt.add(20) as *const u16) } as usize;              // :43
  let sec_base = unsafe { nt.add(24 + opt_sz) };                             // :44
  for i in 0..num_sec { let sec = unsafe { sec_base.add(i * 40) }; … }        // :51-52
  ```
  `e_lfanew` is read as a signed `i32` then cast to `usize` and used as an offset
  with no bounds check; a negative `e_lfanew` (or one pointing outside the image)
  makes `module_base.add(e_lfanew)` read arbitrary memory, and the subsequent
  `num_sec`/`sec_base`/per-section reads walk that garbage.
- **描述:** In practice `module_base` is a real loaded module (passed by
  `bootstrap_check` from the loader list), so `e_lfanew` is valid. But
  `check_preservation` is `pub unsafe` and takes an arbitrary `*const u8`; any
  caller passing a non-PE or partial buffer (e.g. a mismatched `module_base`)
  gets an OOB read walk. The loop bound `num_sec` is also attacker/corruption-
  controllable with no cap (unlike `resolve.rs` which caps loader walks at
  256/512).
- **影响:** Defensive only — the sole caller (`bootstrap_check`, `:111`)
  validates the base against the loader list first. Latent robustness gap if a
  second caller is ever added.
- **修复:** Validate `e_lfanew > 0 && e_lfanew < size_of_image - 256` and cap
  `num_sec` (e.g. `< 96`) before the loop.

### [LOW] NEW-8 — `BeaconGetSpawnTo` uses `static mut` buffer (data race if BOF spawns threads)
- **位置:** `bof.rs:494-513`
- **状态:** NEW
- **已核验:**
  ```rust
  static mut SPAWN: [u8; 2048] = [0; 2048];   // :500
  … copy TEMPLATE into SPAWN each call …       // :505-510
  ```
  The comment asserts "single-threaded (beacon loop)." That holds for the beacon
  loop itself, but a BOF's `go()` runs arbitrary C code; some community BOFs
  (and the injection selftests) create threads that outlive `go()`. If two
  threads call `BeaconGetSpawnTo` concurrently (or one calls it while another's
  `CreateProcess` still reads the returned pointer), the re-stamp at `:505-510`
  races the prior caller's read. The prior audit's NEW-12 noted the same
  single-threaded assumption for `BeaconCleanupProcess`; this extends it.
- **影响:** Corrupted spawn-to path in a concurrency edge case (BOF threads).
  Unlikely but possible given the injection test surface.
- **修复:** Document the single-threaded contract in the BOF-facing header, or
  return a per-call `Vec`-backed buffer registered with `crate::mem` (the BOF
  copies it into its own `PROCESS_INFORMATION` usage anyway).

---

## 3. Audit of the in-progress fixes (new code = new bugs)

### 3.1 CRIT-3 fix — T-REX honest Unknown banner (SOUND)
- **位置:** `trex/mod.rs:160-216` (new), `beacon.rs:362-378` (consumer), `trex/mod.rs:901-909` (selftest)
- **已核验:**
  - New const `TREX_SCANNERS_IMPLEMENTED: bool = false` (`:172`) with a thorough
    doc comment (`:159-171`) naming every stub and the P0-6 plan ref.
  - `assess_user_mode` (`:176`) early-returns at `:193` with
    `ThreatTier::Unknown` + a banner string `"⚠ T-REX RECON UNIMPLEMENTED: output
    is NOT trustworthy… Do not base evasion decisions on this."` (`:190-192`)
    BEFORE any stubbed scanner runs. The stubs at `:804-858` are now unreachable
    dead code until the const flips.
  - The operator-facing path (`beacon.rs:362-378`) prints `tn = tier_names.get(
    assessment.tier as usize).map_or(&b"Unknown"[..], …)` (`:366`) — `Unknown` is
    index 5, outside the 5-element `tier_names` array, so `get` returns `None` →
    falls back to `"Unknown"` (the `map_or` default). The banner is appended
    verbatim (`:377`). Correct.
  - The selftest `nyx_selftest_trex` (`:901`) computes `0xE0 + tier` (`:907`);
    for `Unknown` (5) that's `0xE5`, and `write_report` (`:943-950`) has a `_ =>
    "Tier: Unknown\r\n"` catch-all arm. Correct.
- **评价:** Sound and thorough. The fix surfaces the unimplemented state honestly
  on all three paths (const doc, early-return banner, consumer display, selftest
  exit code/report). One residual: `assess_kernel` (`:220-238`) is ALSO fully
  stubbed (it calls `enumerate_kernel_modules`/`query_code_integrity`/etc. which
  are the same class of no-op) but returns a default `KernelPosture` with no
  Unknown banner — an operator calling `assess_kernel` with a BYOVD handle gets a
  silently-empty posture. Recommend the same `KERNEL_SCANNERS_IMPLEMENTED` gate.

### 3.2 HIGH-NEW-BOF1 fix — BeaconDataExtract checked_add (SOUND, one nit)
- **位置:** `bof.rs:368-392`
- **已核验:** The fix splits the guard into two stages:
  ```rust
  let len = *((*d).buffer as *const i32);
  if len < 0 { … return null; }                          // :369-374
  let len_u = len as usize;                              // :379
  let need = 4usize.checked_add(len_u).unwrap_or(usize::MAX); // :380
  if need > left as usize { … return null; }             // :381-386
  ```
  - `len < 0` rejected first (`:369`), so `len as usize` (`:379`) is safe (no
    sign extension to a huge usize).
  - `checked_add` (`:380`) handles the `len ≈ i32::MAX` overflow that the old
    `4 + len` (i32 wrap to negative) allowed. The `unwrap_or(usize::MAX)` makes
    any overflow fail the `need > left` check. Correct.
  - `left` is guaranteed `>= 4` by the prior block (`:362`), so `left >= 4 > 0`
    → `left as usize` (`:381`) is a safe positive cast. Correct.
  - Cursor advance uses `len_u` (`:388`), bounded by the passed check. Correct.
- **评价:** Sound. The root cause (i32 arithmetic overflow) is genuinely fixed,
  not just the symptom. **Residual nit:** the length is still read via an
  unaligned raw deref `*((*d).buffer as *const i32)` (`:368`) — undefined
  behavior on architectures requiring alignment (x64 tolerates it, but it is
  still UB the optimizer may exploit). The same unaligned `*(i32*)` read pattern
  recurs in `BeaconGetInt` (`:406`), `BeaconGetShort` (`:422`), and the parser.
  Recommend `u32::from_le_bytes` via `read_unaligned` everywhere a length/int is
  read from the wire/args blob. Non-blocking.

### 3.3 HIGH-NEW-BOF2 fix — selftest feature gating (PARTIAL, see NEW-2)
- **位置:** `selftests.rs` (50 exports), `Cargo.toml` (feature def), `lib.rs:128` (mod decl)
- **已核验:**
  - `Cargo.toml` adds `[features] default = []` and `selftest = []` with a clear
    comment ("Production builds (default features) exclude all selftest exports").
  - `lib.rs:128` is still `pub mod selftests;` under only `#[cfg(target_os =
    "windows")]` — NOT gated by `feature = "selftest"`. So the MODULE still
    compiles in production; only the 50 `#[no_mangle]` exports are cfg'd out.
    This means all the helper functions (`write_marker` `:1850`, `diag_byte`
    `:2560/2635`, `ensure_rt` `:38`, `nt_create_file_*` `:1439/1543`, the
    `hex_u32`/`dec_u32`/`format_status` formatters) still compile into the
    production binary, along with their string literals (`nyx_bof_diag.txt`,
    `nyx_etwti_status.txt`, `C:\nyx\…`, etc. — see `write_marker` callers). With
    LTO + strip the dead code *should* be eliminated, but the `nyx_`-prefixed
    string literals are only referenced by dead exports, so LTO is load-bearing
    here — a non-LTO build (or a future helper called from a live path) would
    re-introduce the artifact strings. Worth verifying the release profile
    actually LTO-strips them.
  - 50 of 51 exports in `selftests.rs` correctly carry `#[cfg(feature =
    "selftest")]` directly above `#[no_mangle]` (verified by
    `grep -nB2 'extern "system" fn'`). `noop_veh_handler` (`:2803`) is the
    exception (NEW-2).
- **评价:** The feature-gating mechanism is correct and the gating is applied
  consistently within `selftests.rs`. Three gaps:
  1. `nyx_selftest_trex` in `trex/mod.rs:900` is ungated (NEW-2) — same class of
     export, different file, missed by the patch.
  2. `noop_veh_handler` (`selftests.rs:2803`) is ungated (NEW-2).
  3. `pub mod selftests` (`lib.rs:128`) is ungated, so the module + its `nyx_*`
     string literals still compile; LTO is relied upon to strip them. Recommend
     gating the `mod selftests;` line itself behind `#[cfg(feature = "selftest")]`
     (with a `#[cfg(not(feature = "selftest"))] pub mod selftests {}` empty shim
     if any live path references the module path) so the strings never enter the
     build graph.

### 3.4 `selftests.rs` side-fix: `ImplantKeypair::generate` now returns `Result`
- **位置:** `selftests.rs:774-778`, `:816-819` (the non-diff context shows the `Ok`/`Err` match)
- **已核验:** The diff changes `let kp = ImplantKeypair::generate();` to a
  `match` handling `CsprngFailed` (`exit(0xAF)`) and `ZeroScalar` (`exit(0xAE)`).
  This tracks a protocol-crate API change (generate now fallible). The handling
  is correct (distinct exit codes for each failure mode, matching the docstring
  at `:760-773`). Sound.
- **评价:** Good — no new bug. Note these two functions
  (`nyx_selftest_csprng`, `nyx_selftest_loopdiag`) are now feature-gated, so
  this fix only ships in test builds anyway.

---

## 4. Verified-clean areas (INFO)

- **`bof.rs` W^X section mapping** (`:707-791`): each section RW during
  copy+reloc, code flipped to `PAGE_EXECUTE_READ` (`:783`) before `go()`, data
  stays RW. At the `go()` transmute (`:811`) no page is W+X. Correct fix for the
  prior RWX-blob CRITICAL. (The NEW-1 leak is a separate, post-`go()` issue.)

- **`bof.rs` out_push / capture buffer** (`:88-100`): bounds-checked against
  `OUT_CAP` (16 KiB), truncates cleanly. `captured_output` (`:113`) returns
  exactly `OUT_LEN` bytes. Sound.

- **`bof.rs` BeaconDataParse / args lifetime** (`:332-348`, `:803-815`):
  `args_blob` is a local `Vec` that lives through `go()`; `ARGS_PTR` is cleared
  by `reset_capture` at the start of each `run()` (`:806`) so no cross-run
  dangling read reaches a BOF. Sound.

- **`hashdump.rs` oplock-safe probe** (`stream_file:50-140`): probes with
  `open_file_nosync` (non-synchronous) first → `STATUS_SHARING_VIOLATION`/
  `STATUS_ACCESS_DENIED` returns immediately instead of hanging; falls back to
  `RegSaveKeyW` only on those statuses. The comment at `:70-72` correctly notes
  that the subsequent synchronous `do_download` is safe once the probe won the
  oplock. Sound design — the one footgun (the selftest that bypassed it) is now
  feature-gated.

- **`fs.rs` `allowed()` substring approach** (`:204-215`): robust against
  `./`, `\\`, trailing space/dot, ADS `::$DATA`, 8.3 short names — all still
  contain the literal `\config\sam` substring. (Caveat: bypassable via `..` —
  see NEW-5; the substring logic itself is sound, the normalization is the gap.)

- **`screenshot.rs` integer hardening** (`:419-422`): `checked_mul` for pixel
  count and `×4` byte count, `MAX_PIXELS` cap, BMP magic + size validation in
  `read_file`. GDI handle teardown on every path inside the capture closure.
  Sound.

- **`postex.rs` token ops** (`steal_token`, `use_token`, `revert`, `getuid`):
  handles closed on all paths (`close(primary)` `:238`, `close(prev)` `:356`);
  `IMPERSONATION` atomic with `Relaxed` (single-threaded beacon — acceptable);
  `make_token` closes the prior token before overwriting (`:354-356`). Sound
  aside from the zeroization gap (MED-NEW-BOF6).

- **`pivot.rs` buffering** (`:514-527`, `:586`): fixed 4096-byte recv buffer,
  send loops until flush or hard-error, no unbounded buffering; channel table
  fixed at `MAX_CHANNELS=16` (`:72`). Sound aside from NEW-8 (SOCKS5 BIND reuse)
  and the documented WOULDBLOCK-as-hard-error choice.

- **`recon.rs` table parsing** (`:639, :809, :834`): all buffer reads
  `unwrap_or(0)`-defended, sizes capped at 1 MiB, row offsets bounds-checked
  (`off + ROW > buf.len() → break`). Sound.

- **`envprobe.rs` VM detection**: correctly excludes `Microsoft Hv` (VBS false
  positive), vendor-OUI signatures only, RDTSC as corroborator. Sound.

- **`trex/melt.rs` wipe primitives** (`secure_zero:38-43`,
  `wipe_and_free_pages:65-83`, `close_all_handles:108-113`): `write_volatile` +
  `compiler_fence(SeqCst)`; RX→RW before zero+free; bails on `NtProtect` failure;
  skips pseudo-handles `-1/-2`. Sound (only the arming-guard gap, HIGH-7, and the
  fixed-PAGE_SIZE wipe in `wipe_and_free_pages` are notes).

- **`keylog.rs` dual-writer avoidance** (`poll_once` skips when hook active):
  the beacon-thread `buf_push` and hook-thread `buf_push_release` never race on
  `BUF`; the dump path's `Acquire` load pairs with the writer's `Release` store
  for the byte visibility (the lost-keystroke race in NEW-6 is a different,
  reset-window issue).

---

## 5. Priority ordering

1. **NEW-1** (HIGH) — BOF section leak: unbounded memory growth + durable RX IOC.
   Easy fix (VirtualFree loop after `go()`), high payoff.
2. **HIGH-6** (deaddrop truncation + NEW gist-id truncation) — silent exfil
   failure; total dead-drop breakage for classic gist IDs.
3. **NEW-2** (HIGH/MED) — finish the selftest gating: `nyx_selftest_trex` +
   `noop_veh_handler` + gate `mod selftests`.
4. **CRIT-3 residual** — extend the Unknown banner to `assess_kernel` (same
   stub class, same false-security-guarantee risk).
5. **HIGH-7** (melt arming guard) — still latent (zero callers) but `pub`.
6. The cluster of MED-NEW-BOF4/5/6/7/8/9/10 — all still present, none fixed
   this cycle; roster them into the next fix batch.
7. **NEW-3** (printf parser) — correctness for real-world BOFs; no memory-safety
   impact but undermines BOF output reliability.

The 07-10 fix batch landed three correct, well-documented fixes (CRIT-3,
HIGH-NEW-BOF1, and 96% of HIGH-NEW-BOF2). The remaining work is closing the
selftest-gating tail (NEW-2), adding the post-`go()` cleanup (NEW-1), and
addressing the carry-over MED/HIGH items that were not in this batch.
