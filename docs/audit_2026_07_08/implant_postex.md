# Implant post-exploitation & T-REX subsystem — deep audit (2026-07-08)

**Scope:** `crates/implant-win/src/` — `bof.rs`, `hashdump.rs`, `keylog.rs`,
`screenshot.rs`, `fs.rs`, `pivot.rs`, `postex.rs`, `recon.rs`, `hostinfo.rs`,
`envprobe.rs`, `resolve.rs`, `selftests.rs`, and `trex/` (`mod.rs`, `cleanup.rs`,
`delivery.rs`, `melt.rs`, `exfil/mod.rs`, `exfil/deaddrop.rs`).
**Method:** line-by-line static review; every claim cites lines actually observed.
**Authorization:** internal red-team C2 improvement — no weaponizable payloads.

---

## 1. Baseline findings — re-verification

| ID | Finding | Cited lines | Status |
|----|---------|-------------|--------|
| CRIT-3 | T-REX recon all stubs | `trex/mod.rs:779-847`, `assess_user_mode:162-191` | **CONFIRM** |
| HIGH-6 | deaddrop 16 KiB truncation | `trex/exfil/deaddrop.rs:140-141` | **CONFIRM** |
| HIGH-7 | melt no arming guard | `trex/melt.rs:133-144` | **CONFIRM** (latent — see note) |
| LOW-8 | trex Defender/ATP matching | `trex/mod.rs:709` (now `:711`/`:718`) | **CONFIRM** + worse (dead branch) |
| LOW-9 | delivery APC not alertable | `trex/delivery.rs:246` | **CONFIRM** |
| (prior) | resolve.rs forwarder bounds | `resolve.rs:459-467, 500` | **FIXED** |

### [CRITICAL] CRIT-3 — T-REX assessment is a no-op returning `Clean` always
- **位置:** `trex/mod.rs:779-847` (all internal helpers), `assess_user_mode` at `:162-191`, `get_process_mitigation_policy` stub at `:836-839`
- **已核验:** Every recon primitive is a stub returning a null/0/empty/false sentinel:
  ```rust
  unsafe fn create_toolhelp_snapshot() -> Handle { core::ptr::null_mut() }   // :779
  unsafe fn process32_first(...) -> i32 { 0 }
  unsafe fn open_registry_key(...) -> HKey { core::ptr::null_mut() }         // :793
  unsafe fn reg_enum_key(...) -> i32 { -1 }
  unsafe fn wmi_query_av_products(...) {}                                    // :799-801
  unsafe fn open_sc_manager() -> Handle { core::ptr::null_mut() }
  unsafe fn get_process_mitigation_policy(...) -> i32 { 0 }                  // :836
  ```
  `assess_user_mode` (`:162`) calls `scan_processes` → `scan_service_registry` →
  `scan_wmi` → `scan_service_manager` → `query_mitigations`, but each short-circuits
  on a null handle / zero return. `query_mitigations` calls the real `query_cfg`/
  `query_cet`/… which in turn call the stub `get_process_mitigation_policy`
  (`ok == 0` → flags never set).
- **描述:** The entire T-REX decision engine is unimplemented. `determine_tier`
  (`:623`) sees an empty `products` Vec and all-false `mitigations` → always
  returns `ThreatTier::Clean`.
- **影响:** **False security guarantee operators rely on** (CRITICAL per rubric).
  An operator invoking `assess_user_mode()` on a fully-EVR'd CrowdStrike + HVCI
  box is told `"Minimal: indirect syscalls + sleep obfuscation sufficient. No
  kernel evasion needed."` (`recommend`, `:656`) and will then run a soft-target
  evasion profile that gets caught. The recon result is **always wrong in the
  dangerous direction** (under-reporting defenses). `nyx_selftest_trex`
  (`:875`) also writes a misleading `C:\nyx\trex_report.txt` (see selftests finding).
- **修复:** Implement the PEB-walk resolvers (the file is scaffolded for
  `CreateToolhelp32Snapshot`/`RegOpenKeyExW`/`OpenSCManagerW`/`NtQuerySystemInformation`
  via `crate::resolve::export_addr`, the same pattern every other module here uses).
  Until then, `assess_user_mode` must return `ThreatTier::Unknown` and `recommend`
  must say `"assessment not implemented"`, not `Clean`.

### [HIGH] HIGH-6 — deaddrop truncates payload to 16 KiB (CONFIRM) + response to 4 KiB
- **位置:** `trex/exfil/deaddrop.rs:140-141` (encode buffer), `:191` (response buffer)
- **已核验:**
  ```rust
  let mut b64_buf = [0u8; 16384];                       // :140
  let b64_len = base64_encode(encrypted_payload, &mut b64_buf); // :141
  ```
  `base64_encode` (`:82-102`) silently stops writing once `wi + 4 > output.len()`
  (`if wi + 4 <= output.len() { … }` at `:96`) — it does **not** error on overflow,
  just truncates. The body is then assembled from `&b64_buf[..b64_len]` (`:148`).
  Separately, the response reader uses `let mut resp = [0u8; 4096];` (`:191`) and
  caps `total` at 4096 (`remain = (resp.len() - total).min(1024)`, `:195`).
- **描述:** Any recon report > ~12 KiB raw (16 KiB base64) is silently truncated
  before upload; the C2 then retrieves a partial gist. The gist-id JSON usually
  fits in 4 KiB so the response cap is lower-risk, but a verbose API response
  (rates, owner, timestamps) can push `"id"` past 4 KiB on some accounts.
- **影响:** Silent data loss in the exfil path — the operator receives a truncated
  report with no error signal. For a dead-drop resolver whose entire purpose is
  "C2 never sees the implant's IP," a silently-incomplete report is an attribution/
  correctness hazard.
- **修复:** Either chunk the payload across multiple gists, or grow `b64_buf`
  dynamically (the `heap::Vec` is available — `body` already is one) and propagate
  an `Err` when `base64_encode` would overflow. Return `Err` (not silent truncation)
  from `base64_encode` on overflow.

### [HIGH] HIGH-7 — `melt::self_destruct` has no arming guard (CONFIRM, latent)
- **位置:** `trex/melt.rs:133-144`
- **已核验:**
  ```rust
  pub unsafe fn self_destruct(
      sensitive_buffers: &mut [&mut [u8]],
      rx_pages: &[*mut c_void],
      module_base: Option<*mut u8>,
      handles: &[isize],
  ) -> ! {
      secure_zero_many(sensitive_buffers);
      wipe_and_free_pages(rx_pages);
      if let Some(base) = module_base { zero_pe_header(base); }
      close_all_handles(handles);
      terminate_self()
  }
  ```
  No `ARMED`/`static AtomicBool` gate; the fn performs the irreversible 5-step wipe
  unconditionally on first call. **Nuance:** a repo-wide grep shows `self_destruct`
  / `melt::` has **zero callers** in `src/` — the module is currently dead code,
  so this is latent, not live. But it is `pub` and exports-ready.
- **描述:** Any future code path (panic handler, a malformed command wired to melt,
  a beacon-loop bug) that reaches `self_destruct` permanently kills the implant with
  no second chance. The signature also takes raw pointers with no validation —
  `wipe_and_free_pages` will `NtProtect`+`write_bytes` whatever it's handed.
- **影响:** Permanent implant death from an accidental call (false security
  guarantee / data loss per rubric).
- **修复:** Require an `armed: &AtomicBool` that the operator must explicitly set
  via a dedicated `Melt { arm }` two-step command (set arm → confirm → fire), and
  validate `rx_pages`/`module_base` are within the known image range before wiping.

### [LOW] LOW-8 — `msmpeng` misclassified as Defender ATP + dead code branch
- **位置:** `trex/mod.rs:711` (process match), `:718` (dead branch), `:760` (driver match)
- **已核验:**
  ```rust
  // :711  — msmpeng mapped to ENTERPRISE EDR
  if lower.contains("mssense") || lower.contains("msmpeng") { return Some(Vendor::MicrosoftDefenderATP); }
  // :718  — unreachable: msmpeng already returned above
  if lower.contains("msmpeng") && lower.contains("defender") { return Some(Vendor::Defender); }
  ```
  And `is_edr_driver` (`:752`): `n.contains("windefend") || n.contains("wdfilter")`.
- **描述:** `MsMpEng.exe` (`msmpeng`) is the **consumer** Defender antimalware
  service engine present on every default Windows install; the ATP/EDR process is
  `MsSense.exe` (`mssense`). Mapping `msmpeng` → `MicrosoftDefenderATP` (line 711)
  means a vanilla consumer-Windows box is classified as having enterprise EDR. The
  `:718` `Vendor::Defender` branch is dead — `msmpeng` already matched at `:711`.
  `determine_tier` (`:624`) puts `MicrosoftDefenderATP` in the `has_enterprise_edr`
  set, so this drives tier escalation to `EnterpriseEDR`/`Fortress`. Likewise
  `wdfilter.sys`/`windefend` are consumer Defender drivers present on all Windows,
  flagged as EDR drivers in `is_edr_driver`.
- **影响:** Wrong tier on every consumer Windows host → over-evasive recommendation
  (HWBP blind + LACUNA ghost frames) burned on a soft target, increasing detection
  surface for no benefit. (Lower severity than CRIT-3 only because the whole engine
  is stubbed anyway — once implemented, this becomes a real mis-classification.)
- **修复:** Move `msmpeng` to the `Vendor::Defender` (consumer) branch and drop the
  dead `:718` line; key ATP detection on `mssense` (SenseCE) + the `Sense` service.
  In `is_edr_driver`, only treat `wdfilter`/`windefend` as EDR when paired with a
  `mssense`/`Sense` process hit, not standalone.

### [LOW] LOW-9 — `delivery` queues a normal APC to a non-alertable thread
- **位置:** `trex/delivery.rs:246` (`section_jacking_inject`, the `nt_queue_apc` call)
- **已核验:**
  ```rust
  (fns.nt_queue_apc)(h_thread, remote_view, remote_view as usize, 0, 0);  // :246
  ```
  `NtQueueApcThread` (user APC) only fires when the target thread enters an
  **alertable** wait (`SleepEx(..., TRUE)`, `WaitForSingleObjectEx(bAlertable=TRUE)`,
  etc.). `find_target_thread` (`:184`) picks *any* thread owned by `pid` with no
  check that it is alertable.
- **描述:** If the chosen thread never does an alertable wait (common for UI/main
  threads, or a thread blocked in a non-alertable `WaitForSingleObject`), the
  shellcode APC never dispatches and the injection silently fails to execute while
  the section/view stay mapped (the operator believes injection succeeded).
- **影响:** Silent injection failure (correctness); also leaves a dangling RX view
  in the target (detection surface — an EDR scanning for unmapped executable views
  will see it).
- **修复:** Either (a) target a thread known to be alertable, or (b) use
  `NtQueueApcThreadEx` with the special-user-APC context (`QUEUE_USER_APC_FLAGS`
  on Win11+) which can wake a non-alertable thread, or (c) fall back to
  `NtCreateThreadEx` on the remote view if the APC path can't be confirmed.

### [INFO] resolve.rs forwarder fix — VERIFIED FIXED
- **位置:** `resolve.rs:459-467` (size read), `:500` (bounds check), `:519-537` (`resolve_forwarder`)
- **已核验:** The forwarder-detection bounds check now reads the export
  **directory size** from the PE data directory, not the function count:
  ```rust
  let export_dir_size = *(opt.add(dd_off + 4) as *const u32) as usize;  // :467
  ...
  if (fn_rva as usize) >= dir_start && (fn_rva as usize) < dir_end {    // :500
      return resolve_forwarder(base, fn_rva as usize);
  }
  ```
  The inline comment (`:459-466`) documents the prior root cause (hwbp_blind AV on
  `kernel32!AddVectoredExceptionHandler` → `NTDLL.RtlAddVectored…`).
  `resolve_forwarder` parses `MODULE.Func`, handles abbreviated stems
  (`NTDLL` vs `ntdll.dll`) via `find_module_for_forwarder` (`:550`) and API-set
  contract names (`api-ms-`/`ext-ms-`). `fwd_name_matches_long` (`:651`) is the
  unbounded-length fallback. `nyx_selftest_resolve_forwarder` (`:2776`) exercises it.
- **结论:** Sound. Minor note: `resolve_forwarder` recurses with no depth cap
  (`export_addr_by_hash_pub` → `resolve_forwarder` → `export_addr_by_hash_pub`);
  Windows forwarder chains are ≤1 deep so this is theoretical only.

---

## 2. NEW findings

### [HIGH] NEW-1 — `bof::BeaconDataExtract` integer overflow → OOB read
- **位置:** `bof.rs:368-376`
- **已核验:**
  ```rust
  let len = *((*d).buffer as *const i32);          // :368  attacker/wire-controlled
  if len < 0 || left < 4 + len {                   // :369  4 + len overflows i32
      ...
      return core::ptr::null();
  }
  let p = (*d).buffer.add(4);                       // :375
  (*d).buffer = p.add(len as usize);                // :376  advances by up to 2^31
  ```
- **描述:** `len` is an `i32` read directly from the BOF args blob. The bounds
  guard `left < 4 + len` uses `i32` arithmetic; when `len` is near `i32::MAX`
  (e.g. `0x7FFFFFFF`), `4 + len` wraps to a negative value, so `left < (negative)`
  is `false` and the guard is bypassed. The function then returns a pointer `p`
  into the buffer claiming `len` valid bytes and advances the cursor by `len` —
  both out of bounds. The same `i32` read is unaligned (`*((*d).buffer as *const i32)`),
  a minor UB on its own.
- **影响:** Memory-safety OOB read. A malformed length field in the args blob
  (corrupt wire frame, a buggy BOF, or a second `BeaconDataExtract` whose cursor
  landed in garbage) makes the BOF read heap memory beyond the args buffer and
  advances the parser into unmapped pages → info leak or crash (implant death).
- **修复:** Compare in `usize`: `let need = 4usize.checked_add(len as usize)?;`
  and `if len < 0 || (left as usize) < need { … }`. Read the length with
  `u32::from_le_bytes` via `read_unaligned` instead of a raw `*(i32*)`.

### [HIGH] NEW-2 — `selftests.rs` ships ~40 state-mutating exports + leaks `nyx_*.txt` artifacts
- **位置:** `selftests.rs` throughout — `#[no_mangle] pub unsafe extern "system" fn nyx_selftest_*`
  (lines 54, 168, 187, 373, 401, 422, 449, 491, 537, 598, 627, 654, 672, 703, 718,
  732, 744, 791, 968, 1031, 1089, 1111, 1142, 1158, 1181, 1212, 1240, 1281, 1320,
  1714, 1742, 1758, 1974, 2066, 2162, 2185, 2212, 2276, 2308, 2366, 2394, 2427,
  2455, 2706, 2776, 2841, 2882). `write_marker` at `:1809-1885`.
- **已核验:** These are **not `cfg`-gated** (only `diag_byte` has a
  `#[cfg(nyx_diag)]`/`#[cfg(not(nyx_diag))]` pair at `:2504`/`:2582`; the rest
  compile unconditionally into the production implant). They mutate real state:
  - `nyx_selftest_fs` (`:54`) writes `%TEMP%\nyx_fs_selftest.bin`, renames, copies, mkdir, rm.
  - `nyx_selftest_shell` (`:168`) spawns `cmd.exe /C echo nyx-shell-selftest`.
  - `nyx_selftest_inject` (`:491`) creates `notepad.exe` SUSPENDED + terminates it.
  - `nyx_selftest_inject_armed` (`:1031`) + `nyx_selftest_inject_pool` (`:537`)
    do real module-stomping / section injection into a live process.
  - `nyx_selftest_rm_probe` (`:1714`) `mkdir`/`echo`/`rmdir` via shell.
  - `nyx_selftest_keylog` (`:401`) installs a real `WH_KEYBOARD_LL` hook.
  - `write_marker` (`:1809`) emits predictable files: `nyx_bof_diag.txt`,
    `nyx_etwti_status.txt`, `nyx_fs_combos.txt`, `nyx_rm_probe.txt`,
    `nyx_fs_path.txt`, `nyx_fs_stack_status.txt`, `nyx_fs_export_status.txt`,
    `nyx_fs_status.txt`, `nyx_alloc_probe.txt`, `nyx_ntclose_status.txt`,
    `nyx_rt_probe.txt`, `nyx_gap_pool.txt`, `nyx_fs_selftest.bin`, … all under
    `%TEMP%` (or `C:\Windows\Temp`), plus `C:\nyx\trex_report.txt` (trex) and
    `C:\nyx\hwbp_diag.txt` (`:2514`, diag-gated).
- **描述:** Every `nyx_selftest_*` symbol is a stable, discoverable export name in
  the implant's PE export table. An analyst (or an EDR heuristic) can enumerate them
  and invoke any via `rundll32 nyx_implant_win.dll,nyx_selftest_*` — each then writes
  `nyx_*`-prefixed marker files, spawns processes, or injects. The `nyx_` prefix and
  the export names themselves are trivial YARA/signature targets.
- **影响:** Major forensic/opsec liability baked into the production binary: stable
  IOC export names + on-disk `nyx_*.txt` artifacts + side-effecting entrypoints
  (process spawn, injection, screenshot capture). This is the single biggest
  avoidable detection surface in the audited files.
- **修复:** Gate the entire module behind `#[cfg(nyx_selftest)]` (off in release/PIC
  builds). If any must ship for field diagnostics, strip their names
  (`#[no_mangle]` → randomized), move markers behind `DIAG_ENABLED`, and never write
  to a fixed `C:\nyx\` path.

### [HIGH] NEW-3 — `nyx_selftest_hashdump_diag` hangs the beacon forever
- **位置:** `selftests.rs:717-724`
- **已核验:**
  ```rust
  pub unsafe extern "system" fn nyx_selftest_hashdump_diag() {
      let rt = ensure_rt().unwrap();
      // ... if NtCreateFile on a hive locked by the SAM service hangs,
      // this selftest won't reach the exit. (Confirmed: it hangs.)  ← :722
      let _ = crate::fs::do_download(rt, "C:\\Windows\\System32\\config\\SAM"); // :723
      unsafe { exit(1) }; // reached only if it didn't hang
  }
  ```
- **描述:** `do_download` opens the live SAM hive with `FILE_SYNCHRONOUS_IO_NONALERT`
  (see `fs.rs:437`); the SAM service holds an exclusive oplock, so `NtCreateFile`
  **blocks forever** waiting for the oplock to break. The code's own comment
  acknowledges it hangs. There is no timeout. (`hashdump::stream_file` correctly
  uses `open_file_nosync` to avoid exactly this — `:56-65` — but this selftest
  bypasses it and calls `do_download` directly.)
- **影响:** A footgun that permanently bricks the implant (the beacon loop never
  returns). Combined with NEW-2 (it's a shipped `#[no_mangle]` export), an analyst
  invoking it, or an operator mis-clicking, kills the session with no recovery.
- **修复:** Delete the export, or route it through `hashdump::do_hashdump_vec`
  (which uses the oplock-safe probe). Never call `do_download` on a live hive path.

### [MEDIUM] NEW-4 — `hashdump` writes SAM/SYSTEM hive to a plaintext temp file (cleanup best-effort)
- **位置:** `hashdump.rs:671-674` and `:709-720` (temp paths), `:93` (cleanup), `:766-779` (`delete_temp`)
- **已核验:** `save_hive_fallback` does `RegSaveKeyW` to `C:\Windows\Temp\SAM.hive`
  (or `SAM_<tick>.hive`), then `do_download` streams it, then `delete_temp` is called
  (`:93`). The temp file is created with `lpSecurityAttributes = NULL` (`:694`,
  `:720`) → default ACL; on `C:\Windows\Temp` that ACL can allow non-SYSTEM reads.
  `delete_temp` (`:766`) is best-effort and only runs on the happy path.
- **描述:** The SAM hive (encrypted at rest by the boot key, but still credential
  material — the NTLM hashes live in it) is materialized on disk with no explicit
  security descriptor. If the beacon is killed mid-stream (operator abort, link
  drop, blue-team quarantine) between `RegSaveKeyW` and `delete_temp`, the `.hive`
  persists. The alt-name fallback (`:709`) writes a *second* file and only cleans
  the original, not always itself on failure.
- **影响:** Credential material left at rest on the target, readable under the
  default Temp ACL — a secret-exposure + forensic-artifact hazard.
- **修复:** Create the temp file with a NULL-DACL (owner-only) security descriptor
  via `SECURITY_ATTRIBUTES`; `melt::secure_zero` the streamed bytes after send; and
  register the temp path so `melt::self_destruct` deletes it on exit.

### [MEDIUM] NEW-5 — `hashdump` / `postex::make_token` do not zeroize secrets
- **位置:** `hashdump.rs:206-216` (`joined` buffer), `postex.rs:339-356` (`wpass` stack buffer)
- **已核验:** `do_hashdump` joins all hive chunks into `joined: Vec<u8>` (`:206`) and
  returns it; neither `joined` nor the per-chunk `Vec<u8>` are zeroed after send.
  The implant heap is the `ntalloc` bump allocator (HIGH-8 baseline: never frees), so
  the SAM/SYSTEM bytes sit in committed memory for the process lifetime.
  `make_token` (`:298`) widens the password into `wpass: [u16; 256]` on the stack
  (`:339`) and never overwrites it after `LogonUserW`.
- **影响:** Credential material (NTLM-hash-bearing hive bytes; plaintext password)
  persists in implant memory/stack — recoverable by a memory forensic capture
  (Volatility, or a live `procdump` + strings).
- **修复:** After the response is built, `melt::secure_zero` the hive chunk Vecs and
  `joined`; `secure_zero(&mut wpass)` at the end of `make_token` (and `wuser`/`wdom`
  for hygiene).

### [MEDIUM] NEW-6 — `fs::fileop_cp` reads the entire source into memory (OOM)
- **位置:** `fs.rs:789-843`
- **已核验:**
  ```rust
  let src_chunks: Vec<Vec<u8>> = unsafe { … loop { … out.push(buf[..got].to_vec()); } … }; // :789-842
  ```
  Unlike `do_download` (which streams 128 KiB chunks over the wire), `cp` is a
  local copy with no wire cap, so it buffers the **whole file** into a `Vec<Vec<u8>>`
  before writing the destination. The comment (`:786-788`) acknowledges this.
- **影响:** Copying a multi-GB file OOMs the implant (`panic=abort` → implant death).
  An operator `cp` of a large VHD/pagefile/database crashes the session.
- **修复:** Stream: open src + dest, read one `CHUNK`, write one `CHUNK`, repeat.
  No need to hold the whole file.

### [MEDIUM] NEW-7 — `fs::fileop_mv` silently truncates destination to 260 wchars
- **位置:** `fs.rs:747-751`
- **已核验:**
  ```rust
  let mut info: FileRenameInformation = core::mem::zeroed();
  let dn = destbuf.len().min(info.file_name.len());   // file_name is [u16; 260]
  info.file_name[..dn].copy_from_slice(&destbuf[..dn]);
  info.file_name_length = (dn * 2) as u32;
  ```
  If `dest` is longer than 260 UTF-16 units, `dn` caps at 260 and the rename
  targets a **truncated** path — silent data-integrity corruption (file lands at the
  wrong, truncated name with no error).
- **影响:** Silent wrong-target rename on long paths; the operator is told `Ok`.
- **修复:** Return `Err` when `destbuf.len() > 260`, or allocate `FileRenameInformation`
  with a variable-length trailing `file_name` (the struct is documented to support
  arbitrary-length names — `info_len = 20 + file_name_length` already handles it at `:760`).

### [MEDIUM] NEW-8 — `pivot` SOCKS5 BIND: multiple peers collide on one chan id, listener never auto-closes
- **位置:** `pivot.rs:597-614` (accept reuses listener chan), `:483` (listener stays open)
- **已核验:** In `pump_channels`, a `listening` channel calls `try_accept` (`:598`);
  on a new peer it does `add_channel_kind(c.chan, peer, false)` (`:603`) — the peer
  reuses the **listener's** `chan` id. The listener itself is never closed after the
  first accept. If a second connection arrives (backlog is 1, but accept fires across
  cycles), a second peer is added under the same `chan`. `slot_of_active` (`:157`)
  returns the first match, so operator data routes to one peer and the others starve;
  their recv data is indistinguishable on the wire.
- **影响:** SOCKS5 BIND semantics are broken for any callback scenario with >1
  connection; data misroutes; the listener lingers as a forensic footprint.
- **修复:** After the first accepted peer, close the listener (`closesocket` + set
  `CHANNELS[i] = None`) and either reject further accepts or assign them new chan ids.

### [MEDIUM] NEW-9 — `trex/cleanup::wipe_prefetch` can panic (OOB slice) on a long name
- **位置:** `trex/cleanup.rs:115-142` (`wipe_prefetch`)
- **已核验:**
  ```rust
  let mut path = [0u16; 128];
  let prefix: &[u16] = &[ … '\\','?','?','\\','C',':','\\','W','i','n','d','o','w','s','\\','P','r','e','f','e','t','c','h','\\' ]; // 25 units
  let pl = prefix.len();
  path[..pl].copy_from_slice(prefix);
  path[pl..pl+name.len()].copy_from_slice(name);   // panics if pl+name.len() > 128
  ```
  A prefetch `name` longer than 103 UTF-16 units (e.g. a mangled/long image name)
  makes `pl + name.len() > 128` → slice OOB → panic → `panic=abort` → implant death.
  Also `UnicodeStr { … max: 256, … }` (`:135`) is hardcoded regardless of actual
  buffer length (a malformed UNICODE_STRING if `len > max`).
- **影响:** A long prefetch name passed to the melt cleanup path kills the implant.
- **修复:** Bounds-check `pl + name.len() <= 128` and skip/Err on overflow; set
  `max = (pl + name.len()) * 2`.

### [MEDIUM] NEW-10 — `bof::alloc_near` only probes 64 MiB of the 2 GiB REL32 window
- **位置:** `bof.rs:616-645`
- **已核验:**
  ```rust
  const STEP: usize = 1 << 20; const WINDOW: usize = (2u64 << 30) as usize; // :618-619
  while hint > floor && tries < 64 { … hint = hint.saturating_sub(STEP); tries += 1; } // :624-636
  alloc(ptr::null_mut(), sz, …)   // :639  fallback: kernel picks — REL32 may overflow
  ```
  The loop probes at most 64 × 1 MiB = 64 MiB below the anchor, then falls back to a
  NULL-hint `VirtualAlloc`. The fallback comment admits "REL32 may overflow."
- **影响:** Under ASLR/crowded address space the near probe fails and the BOF is
  mapped far from the implant image; REL32 calls/`lea` into Beacon-API shims
  overflow the 32-bit displacement → call jumps to garbage → segfault (implant death).
- **修复:** Raise the try budget to cover the full window (`WINDOW / STEP` = 2048
  probes), or scan the region for a free gap via `VirtualQuery` before allocating.

### [LOW] NEW-11 — `keylog` hook-thread `buf_push_release` uses Relaxed load → brief loss after dump
- **位置:** `keylog.rs:592-602` (writer), `:982` (reader reset)
- **已核验:** The hook-thread writer does `let len = BUF_LEN.load(Relaxed)` (`:593`).
  After the beacon's `do_keylog(2)` resets `BUF_LEN.store(0, Release)` (`:982`), a
  store-buffering delay can let the hook thread still observe the old (full) `len`,
  causing it to drop the next 1–2 keystrokes even though space was just freed.
- **影响:** A keystroke or two lost immediately after each dump. Minor fidelity gap.
- **修复:** Load with `Acquire` in `buf_push_release` to pair with the beacon's
  `Release` store.

### [LOW] NEW-12 — `bof::BeaconCleanupProcess` reads handles from an unvalidated BOF pointer
- **位置:** `bof.rs:514-533`
- **已核验:** `let h_proc = *base; let h_thread = *base.add(1);` (`:524-525`) reads two
  `usize` from the BOF-supplied `pi` pointer and `CloseHandle`s them. A BOF passing a
  bogus/unaligned `pi` reads garbage handle values and closes arbitrary handles.
- **影响:** A misbehaving BOF can close random process handles (self-DoS). BOF's
  responsibility, but the shim is a trust boundary.
- **修复:** Best-effort is acceptable for the CS ABI; document that `pi` must be a
  real `PROCESS_INFORMATION`. No code change required, noted for completeness.

---

## 3. Verified-clean areas (INFO)

- **`screenshot.rs` integer-overflow hardening** — `:419-422`:
  ```rust
  let pc = w.checked_mul(h).filter(|&c| c <= MAX_PIXELS)?;  // MAX_PIXELS = 16M :67
  let bytes = pc.checked_mul(4)?;
  let mut pixels: Vec<u8> = vec![0u8; bytes];
  ```
  Both the pixel-count and the `×4` byte count use `checked_mul` with `?` bail and a
  `MAX_PIXELS` cap (64 MiB). The later `bi_size_image`/file-size `u32` math
  (`:455, :492, :480`) cannot overflow because `bytes ≤ 64M < u32::MAX`. **Sound.**

- **`screenshot.rs` GDI handle hygiene** — `:424-505`: every DC/bitmap acquired is
  torn down on every path inside the closure; `detach_interactive()` (`:509-340`)
  restores the window station + closes `WinSta0` on all exits. `read_file`
  (`:1033-1112`) validates `BM` magic + declared-size == actual before trusting the
  BMP, defeating truncated/poisoned captures. **Sound.**

- **`bof.rs` W^X section mapping** — `:707-779`: each section is allocated
  `PAGE_READWRITE`, raw bytes copied (`:718-722`), relocations applied while RW
  (`:737-761`), then **code** sections flipped to `PAGE_EXECUTE_READ` (`:763-778`);
  data sections stay RW. At the `go()` transmute (`:799`) no page is W+X. This is
  the correct fix for the prior `win.rs` RWX-blob CRITICAL. **Sound.**

- **`fs.rs` `allowed()` hive guard** — `:162-217`: normalizes slashes, lowercases,
  strips `.`/empty segments, then substring-checks `\config\{sam,system,security,
  software,default}`. Bypass attempts (`..`, `./`, trailing space/dot, ADS `::$DATA`,
  8.3 short names) all still contain the literal `\config\sam` substring and are
  blocked. Applied consistently on upload/download/rm/mv/cp. **Sound** (minor note:
  `..` is not collapsed — defense-in-depth-fragile but not bypassable as written).

- **`fs.rs` oplock-safe hive probe** — `hashdump::stream_file` (`:50-140`) uses
  `open_file_nosync` to probe the SAM/SYSTEM hive before a synchronous read,
  returning `STATUS_SHARING_VIOLATION` immediately instead of hanging the beacon
  loop, then falls back to `RegSaveKeyW`. **Sound design.**

- **`resolve.rs` PEB walk + forwarder resolution** — forwarder fix verified (above);
  ordinal bounds-checked (`:85-87, :495`); loader-list walks are guard-bounded
  (`_guard < 256/512`) against corrupted lists. **Sound.**

- **`pivot.rs` buffering** — recv buffer is fixed `[0u8; 4096]` (`:586`), send loops
  until flush or hard-error (`:515-527`); **no unbounded buffering** (the focus
  concern is not present). Channel table is fixed `MAX_CHANNELS=16` (`:72`) with
  clean add/close accounting. **Sound** (aside from NEW-8).

- **`envprobe.rs`** — VM detection correctly excludes `Microsoft Hv` (VBS false
  positive on physical Win11), treats RDTSC as corroborator-only, uses
  vendor-specific OUI/signatures. `nyx_selftest_envprobe` (`:587`) is read-only
  (queries + exits, no artifact). **Sound.**

- **`hostinfo.rs`** — `beacon_id` (`:227-231`) xorshift32 with a non-zero seed guard
  (`if x == 0 { x = 0x9E37_79B9 }`); `KUSER_SHARED_DATA` read is a documented
  always-mapped page. `is_admin` (`:134-193`) closes the token handle on all paths.
  **Sound.**

- **`keylog.rs` dual-writer avoidance** — `poll_once` (`:775-777`) skips the polling
  scan when `hook_is_active()`, so the beacon-thread `buf_push` and hook-thread
  `buf_push_release` never race on `BUF`. Release/Acquire pairing on the length makes
  the `do_keylog(2)` snapshot consistent. (Aside from NEW-11's brief post-dump gap.)

- **`trex/melt.rs` wipe primitives** — `secure_zero` (`:38-43`) uses
  `write_volatile` + `compiler_fence(SeqCst)` (correct against the optimizer);
  `wipe_and_free_pages` flips RX→RW before zero+free and bails cleanly on
  `NtProtect` failure; `close_all_handles` skips pseudo-handles `-1/-2`.

---

## Summary

- **3 CRIT/HIGH baseline items CONFIRMED** still present (CRIT-3, HIGH-6, HIGH-7);
  LOW-8/LOW-9 CONFIRMED; resolve.rs forwarder **FIXED**.
- **12 NEW findings**: 3 HIGH (bof OOB read, selftests artifact leak, hang footgun),
  7 MEDIUM (hashdump temp-file/secret hygiene, fs cp-OOM/mv-truncation, pivot BIND,
  cleanup panic, alloc_near reach), 2 LOW.
- The **most urgent** are CRIT-3 (false `Clean` verdict endangers operators) and
  NEW-2/NEW-3 (shipped selftests that both leak `nyx_*` IOCs and can brick the
  implant). NEW-1 (bof OOB) is the only true memory-safety bug in a live path.
