# Kernel-Tier Audit — `operator-kernelsdk` + `operator-kernel-cli`

**Scope:** `crates/operator-kernelsdk/src/` (byovd.rs, cfg.rs, etw_deception.rs, etwti.rs, lib.rs, netsec.rs, offsets.rs, pagewalk.rs, pattern_scan.rs, persistence.rs, telemetry.rs) + `src/win/` (driver_load.rs, kernel_base.rs, ksld.rs, mod.rs, pagewalk.rs, pattern_scan.rs, resolve.rs, va_rw.rs) + `src/byovd_drivers/` + `crates/operator-kernel-cli/src/` (main.rs + 4 bins).
**Reviewer:** AuditKernel · **Date:** 2026-07-08 · **Method:** line-by-line static review, every claim grounded in observed code.

---

## 0. Baseline re-verification

### MED-10 — pagewalk no RAM/MMIO validation → **CONFIRMED (still present)**
- **位置:** `crates/operator-kernelsdk/src/pagewalk.rs:107-111`
- **已核验:** the final 4KB-page translation is:
  ```rust
  let page_base = pt_entry & 0x000F_FFFF_FFFF_F000;   // :108
  let offset = va & 0xFFF;                             // :109
  page_base.checked_add(offset).ok_or(PhysReadError::Overflow)  // :110-111
  ```
  `checked_add` guards only against *arithmetic* u64 overflow. There is **no validation** that the resulting physical address falls inside real RAM (vs an MMIO aperture, a RAM hole, or device memory). The same trust gap applies to every intermediate entry PA (`pml4_base + idx*8` at :56, :67, :83, :99 — no bounds/canonicality check on the *physical* address, only the present bit).
- **影响:** a corrupted or attacker-shaped page table (or a stale DTB) directs the BYOVD/KslD physical read/write into MMIO space → undefined device behavior, bus error, or BSOD. `read_process_mem` (netsec.rs:450) and `va_rw.rs:64,85` both feed driver IOCTLs with the PA this function returns, unchecked.
- **状态:** unchanged since baseline; the `PhysReadError::Overflow` arm in `va_rw.rs:47` only maps the arithmetic-overflow case, not the MMIO case.

### LOW-10 — LSASS freeze fixed/predictable dump path → **CONFIRMED (still present)**
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:670-716` (the cited `:673` is the path prefix line)
- **已核验:** the coma dump is written to a deterministic path:
  ```rust
  let prefix = b"\\?\C:\Windows\Temp\nyx_freeze_";   // :673
  let suffix = b".dmp";                                  // :674
  // ... PID appended → \??\C:\Windows\Temp\nyx_freeze_<pid>.dmp
  ```
  The code comment itself concedes it: *“Using a fixed path for simplicity; a real impl would use a random name.”* (`:671`). The directory + name pattern are fully predictable.
- **影响:** trivial Yara/Sigma footprint (`nyx_freeze_*.dmp` under `Windows\Temp`). See NEW-K7 below for the worse half of this (the file is never deleted).

### Baseline claim "72 unwraps all safe" → **STALE COUNT; conclusion holds (by different reasoning)**
A recount of the kernel domain (excluding `target/`):

| Surface | Total `.unwrap*` | In `#[cfg(test)]`/`mod tests` | In prod code | Panic-capable bare `.unwrap()` in prod |
|---|---|---|---|---|
| `kernelsdk/src/**` (incl. `win/`, `byovd_drivers/`) | **98** | 82 | 16 | **0** |
| `operator-kernel-cli/src/**` | 7 | 0 | 7 | **0** |
| **Domain total** | **105** | 82 | 23 | **0** |

- The baseline "72" undercounts by ~33 (current code is 98 unique in kernelsdk; an initial naive `grep -rn` over both `src/` and `src/win/` double-counted `win/` as 110 — the true unique count is 98).
- **All 16 prod unwraps in kernelsdk are safe:** 10 are `unwrap_or`/`unwrap_or_else`/`unwrap_or_default` (e.g. `byovd.rs:251` `path_buf.last().unwrap_or(&1)`, `cfg.rs:217` `from_utf8(...).unwrap_or("")`), and **6 are `try_into().unwrap()` in `cfg.rs:69-70,198-201`** on *fixed-size slice → array* conversions where the slice is a `[0u8;16]`/`[0u8;40]` local read into `[..8]`/`[24..28]` etc. — the slice length is a compile-time constant, so `try_into()` can never fail. Verified at `cfg.rs:67` (`let mut bitmap_buf = [0u8; 16]`) and `:196` (`let mut dir_buf = [0u8; 40]`).
- **All 7 kernel-cli unwraps are `unwrap_or*`** (e.g. `main.rs:372,380,526,527,659`).
- **Conclusion:** the baseline's "all safe" verdict is correct, but it should be re-stated as **"105 unwraps, 0 panic-capable in any non-test path"** — not "72".

---

## 1. NEW findings (beyond baseline)

### [HIGH] NEW-K1 — `silence_edr` WFP filter blocks ALL host outbound IPv4, not the EDR PID
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:314-335` (`block_outbound_for_pid`), consumed at `:263-265`
- **已核验:** the filter is built with `num_filter_conditions = 0` and a single V4 layer:
  ```rust
  f.action_type = 0x0001;            // FWP_ACTION_BLOCK   :319
  f.layer_key = LAYER_ALE_AUTH_CONNECT_V4;                 // :320
  f.num_filter_conditions = 0;       // match ALL traffic  :328
  f.display_data = [pid as u64, 0];  // PID stored ONLY for diagnostics :333
  ```
  `num_filter_conditions = 0` is the documented WFP semantics for "match every connection on this layer". The PID is stuffed into `display_data` (a diagnostic field) — it never becomes a `FWP_CONDITION0`. The struct fields `WfpBlockRule.protocol`/`.port` (`:60-61`) and `pid` are entirely dead to the filter. The code comment at `:322-326` admits it: *"Real impl would use a filter condition for FWP_CONDITION_ALE_USER_ID."*
- **影响:** calling `UserModeEdrSilencer::silence_edr([edr_pid])` installs a high-weight BLOCK filter that cuts **every** outbound IPv4 connection on the host — including the operator's own implant C2 if co-located. This is the opposite of the documented "surgical EDR telemetry silence" (`netsec.rs:55-67`, `lib.rs:240`). Massive IOC (total network blackout) + likely self-DoS. Operators relying on the surgical claim get burned.
- **修复:** build a real `FWP_CONDITION0` array: condition `FWP_CONDITION_ALE_USER_ID` (or `FWP_CONDITION_ALE_APP_ID`) keyed to the EDR PID/image, set `num_filter_conditions` to the count, point `filter_conditions` at it. Add a V6 layer twin (`FWPM_LAYER_ALE_AUTH_CONNECT_V6`) — current code is IPv4-only so IPv6 EDR telemetry is unaffected.

### [HIGH] NEW-K2 — `choke_edr_qos` ignores its PID and throttles the entire host; wrong QoS2 FFI signature
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:807,873-904,911-922`
- **已核验:**
  - The `pid` parameter is never used after being read (search of the function body: `pid` appears only in the signature `:807`). `QOSAddAppFilter` is called with `AppId = core::ptr::null()` (`:901`) and `QOSSetFlow` with `AppId = null()` (`:914`) — both documented as "apply to all flows," i.e. a **global** throttle.
  - The `QOSCreateHandleFn` type is declared as `(*const u16, u32, *mut *mut c_void)` (`:811-815`), but the real Win32 `QOSCreateHandle` is `BOOL QOSCreateHandle(PQOS_VERSION Version, PHQOS QosHandle)` — `Version` is a pointer to a 2-DWORD struct, and the function takes **2** params, not 3. The call at `:872-877` passes 3 args (`null`, `1`, `&mut qos_handle`).
  - `add_filter`/`set_flow` return values are discarded (`let _ = …` at `:898,911`), so failure is invisible.
- **影响:** same "nuclear stub masquerading as surgical capability" class as NEW-K1 — throttling all system flows, not the EDR. The wrong FFI arity is undefined behavior (stack/register mismatch) that will either fail silently or corrupt state on every invocation. The doc string (`:797-802`) claims "Lowest-noise option — no WFP events" which is false for the actual behavior.
- **修复:** either implement real PID-scoped QoS (filter string / `QOSSetFlow` per-flow targeting the EDR's sockets) or mark the tier `UnsupportedPosture` until implemented. Fix the `QOSCreateHandle` signature to the documented 2-arg form.

### [MED] NEW-K3 — `freeze_edr_coma` leaves a full EDR memory dump on disk and never deletes it
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:719-755`
- **已核验:** `CreateFileW(CREATE_ALWAYS)` creates `\??\C:\Windows\Temp\nyx_freeze_<pid>.dmp`, `MiniDumpWriteDump(..., MINIDUMP_WITH_FULL_MEMORY, …)` (`:738-748`) writes the *entire* EDR process address space, then both handles are closed (`:754-755`) but **the file is never deleted.** No `DeleteFileW` anywhere in the function.
- **影响:** a full-memory dump of an EDR process is one of the highest-value forensic artifacts possible — it contains the EDR's internals, detection logic, and possibly the operator's indicators/IOCs dropped into the EDR's heap. Combined with LOW-10's predictable path, this is trivially swept by IR. Also a disk-space hazard (full-memory dumps are GBs).
- **修复:** after the WER coma is confirmed triggered, `DeleteFileW` the dump (the coma persists independent of the file per the comment at `:750-753`). Or write to `NUL` if the driver tolerates it.

### [MED] NEW-K4 — `CallbackNeutralizer::neutralize` ret-stubs the nt! internal dispatcher (slot 0), causing the exact instability the code warns about
- **位置:** `crates/operator-kernelsdk/src/telemetry.rs:76-110` (esp. `:101-106`); contrast `repurpose` at `:159-196`
- **已核验:** `neutralize_array` guards only on `occupied`, `ctx != 0`, `routine != 0`, and `routine >= 0xFFFF_8000_0000_0000` (canonical). It then unconditionally writes `RET_STUB` (`[0xC3]`) to the routine's first byte (`:106`). There is **no ntoskrnl-range skip** — unlike `repurpose`, which at `:159-196` carefully skips any routine inside `[ntoskrnl_base, ntoskrnl_base+size)` and falls back to skipping slot `i==0`. The module doc at `:133-136` explicitly warns: *"slot[0] of each Ps*NotifyRoutine array is the nt! internal dispatcher — overwriting it causes system instability and PatchGuard detection."*
- **影响:** `neutralize()` (the trait method an operator calls for "neutralize all three arrays") ret-stubs the kernel's own PsNotify dispatcher → broken callback dispatch for legitimate Windows components + near-certain PatchGuard bugcheck. The safety reasoning at `:23-25` ("KCFG-safe because the routine is real code") only holds for *external EDR* callbacks, not the nt! dispatcher.
- **修复:** port the ntoskrnl-range (or slot-0) skip from `repurpose` into `neutralize_array`, or require `runtime.ntoskrnl_base/size` to be resolved before permitting `neutralize()`.

### [MED] NEW-K5 — `detach_edr` unlinks EVERY minifilter on the host (nuclear), despite the name
- **位置:** `crates/operator-kernelsdk/src/telemetry.rs:270-299`
- **已核验:** the walk unlinks every entry in `RegisteredFilters` with no name filter:
  ```rust
  while cur != 0 && cur != list_head && unlinked < 256 {   // :286
      let filter_base = cur.wrapping_sub(flt::FLT_OBJECT_PRIMARY_LINK);
      let next = krw.kread_u64(cur)...;
      self.unlink_filter(krw, filter_base)?;               // :291 — unconditional
      unlinked += 1; cur = next;
  }
  ```
  The doc at `:260-263` concedes it: *"nuclear option: detaches ALL minifilters, including non-EDR ones. For surgical EDR-only detach, the operator resolves the target filter by name and calls `unlink_filter` directly."*
- **影响:** calling the trait method `MiniFilterKit::detach_edr` (the obvious entry point; also what the CLI `detach-minifilter` command and the daemon `detach-minifilter` op call — `main.rs:267,577`) rips out every minifilter including Defender, third-party AV, storage filter drivers. System destabilization + massive IOC. The name is actively misleading.
- **修复:** make `detach_edr` take a target filter name (or predicate) and walk-and-match; reserve the all-unlink as an explicit `detach_all`.

### [MED] NEW-K6 — `resolve_kernel_symbol` matches exports by djb2 hash only (collision → wrong kernel VA → BSOD)
- **位置:** `crates/operator-kernelsdk/src/byovd.rs:401-450` (hash compare at `:425,444`)
- **已核验:** the export walk hashes each name with case-insensitive djb2 (`:429-443`) and returns the **first** whose hash equals `djb2(name)` (`:444-447`) — no byte comparison. The full name bytes are read into `ntoskrnl_image[p]` (`:435`) but only hashed, never compared.
- **影响:** djb2 is non-cryptographic with known collisions. The function is used by `win::resolve_offsets` (`mod.rs:328-331`) to resolve `EtwThreatIntProvRegHandle` — a wrong-symbol collision returns the wrong RVA → `EtwTiBlind` writes `0` to an arbitrary kernel address → bugcheck. Unlike the *implant* (which must hash for stealth), this is **operator-side** with no such constraint; a byte comparison is free.
- **修复:** after the hash matches, do a `name_bytes == ntoskrnl_image[name_rva..name_rva+len]` equality check before returning. (Probability over ~2000 ntoskrnl exports ≈ 5e-4 per build, non-zero.)

### [MED] NEW-K7 — daemon: unauthenticated localhost kernel-R/W surface
- **位置:** `crates/operator-kernel-cli/src/main.rs:470-513` (`run_daemon`), dispatch at `:529-596`
- **已核验:** `TcpListener::bind("127.0.0.1:{port}")` (`:470-471`) accepts connections with **no auth token, no ACL, no peer check**. Any local process can connect and post `{"op":"dump-lsass","pid":684}`, `blind-etw`, `hide`, `detach-minifilter` — all of which drive the live kernel primitive.
- **影响:** local privilege escalation / abuse: a low-priv process (or a Defender scan payload) connects and (a) dumps LSASS memory to a world-location, (b) blinds ETW-TI, (c) hides an arbitrary PID. The daemon typically runs as the admin operator, so this grants kernel-tier capability to any local user.
- **修复:** bind to a restricted named pipe / Unix-domain-equivalent with a DACL, or require a shared-secret token in the first line and reject mismatching peers. At minimum verify `peer_addr()` is the expected team-server.

### [MED] NEW-K8 — daemon: predictable `lsass_{pid}.dmp` output in CWD (symlink/preplacement)
- **位置:** `crates/operator-kernel-cli/src/main.rs:540` (daemon) and `:194` (CLI path)
- **已核验:** `let path = format!("lsass_{pid}.dmp");` then `std::fs::write(&path, &dump)`. Written relative to the daemon's CWD, predictable name, no `O_NOFOLLOW`/exclusive-create.
- **影响:** compounding NEW-K7: an unauthenticated local attacker pre-creates a symlink `lsass_<pid>.dmp → C:\Windows\System32\somelib.dll` (or any target); the daemon `CREATE`-style overwrite (`std::fs::write` truncates) clobbers the target with minidump bytes as the daemon's (admin) identity → arbitrary file overwrite. Separately, the dumped credentials are readable by anyone who can list the daemon's CWD.
- **修复:** write to an operator-controlled temp dir with a random suffix, create with exclusive/reject-symlink semantics, and restrict the file ACL to the operator.

### [MED] NEW-K9 — ETW-TI `for_build` floor-matches, contradicting the module's own "NEVER floor-match" warning
- **位置:** `crates/operator-kernelsdk/src/etwti.rs:124-175` (`for_build` → `floor_match`)
- **已核验:** `for_build`'s default arm calls `Self::floor_match(build)` (`:154`), which maps any `build >= 26100` to 26100's layout, `>= 22621` to 22621's, etc. (`:160-174`). This is the exact pattern `offsets.rs` refuses to do: `offsets::for_build` (`:297-310`) returns `None` for unknown builds with the comment *"Does NOT floor-match. A blind floor-match silently gambles the layout is unchanged — wrong on every EPROCESS restructuring → bugcheck."* The ETW module's own header (`:80-81`) repeats: *"NEVER hardcode a single offset across builds — it silently writes the wrong field."*
- **影响:** a future Windows build that restructures `_ETW_GUID_ENTRY::ProviderEnableInfo` (it already moved 0x050→0x060→0x070 across recent builds) will be floor-matched to the last-known offset → `blind()` writes `0` to the wrong kernel field → corruption + no blind (EDR keeps logging) or bugcheck.
- **修复:** make ETW `for_build` return `None` for unknown builds (matching `offsets::for_build`), forcing the PDB/pattern-scan resolver. Drop `floor_match`.

### [MED] NEW-K10 — cfg.rs export-name binary search truncates at 63 bytes → prefix-collision false match
- **位置:** `crates/operator-kernelsdk/src/cfg.rs:204-231`
- **已核验:**
  ```rust
  let cmp_len = name_bytes.len().min(63);              // :215
  krw.kread(..., &mut cmp_buf[..cmp_len]).ok()?;       // :216 — reads only cmp_len bytes
  let cmp = core::str::from_utf8(&cmp_buf[..cmp_len]).unwrap_or("");  // :217
  ...
  } else {  // exact-match arm :222
      ... return the function RVA at ord ...
  }
  ```
  The comparison reads exactly `min(name.len(), 63)` bytes of the *target* export name, then byte-compares against the search name. If a real export is **longer** than the search name but shares its prefix (e.g. searching `"NtCreate"` against an export `"NtCreateFile"`), `cmp` equals `name_bytes` → false exact match → wrong RVA returned.
- **影响:** latent correctness bug in `resolve_export_rva` (used by `locate_cfg_bitmap` to find `LdrSystemDllInitBlock`). For the current single caller (`"LdrSystemDllInitBlock"`, no longer-prefix sibling in ntdll) it's harmless, but any future caller resolving a short name colliding with a longer export gets the wrong CFG bitmap → wrong bit set.
- **修复:** read one extra byte and require it to be NUL (export names are ASCIIZ), or read `max(name.len(), 64)` and compare full ASCIIZ.

### [MED] NEW-K11 — BYOVD `kread`/`kwrite` loop 1 byte per IOCTL (1 MiB LSASS read = ~1 048 576 IOCTLs)
- **位置:** `crates/operator-kernelsdk/src/byovd.rs:297-363`
- **已核验:** both `kread` (`:305`) and `kwrite` (`:340`) iterate `dst.iter_mut().enumerate()` / `src.iter().enumerate()` issuing one `DeviceIoControl` **per byte**, despite the RTCore64 struct supporting `size ∈ {1,2,4}` (comment at `:116-117`). `KernelLsassReader::dump_lsass_with_base` reads `0x10_0000` (1 MiB) via this path (`netsec.rs:503-504`).
- **影响:** ~1M kernel IOCTLs for a single LSASS dump — minutes of wall time and an enormous kernel-IOCTL telemetry burst (any EDR monitoring `NtDeviceIoControlFile`/minifilter on the device sees a 1M-call storm). This both burns the operator and is 4× slower than the driver allows.
- **修复:** chunk at the driver's max width (4 bytes for RTCore64; the Shield/WDTKernel drivers support larger `len`). At minimum coalesce to `size=4` for 4-byte-aligned runs.

### [MED] NEW-K12 — ETW-TI pointer chain has no canonicality validation on intermediate pointers
- **位置:** `crates/operator-kernelsdk/src/etwti.rs:230-254`
- **已核验:** `resolve_is_enabled_kva` checks `guid_entry == 0` (`:236`) and `prov_block_kva == 0` (`:245`) only. A non-zero but user-mode / non-canonical value (e.g. `0x41414141` from a corrupted or version-mismatched chain) passes both guards, is dereferenced, and the final `kwrite_u64(target, 0)` writes to `prov_block_kva + 0x060 + 0` — a wild address. Contrast `persistence.rs:88,95,147` and `telemetry.rs:101,172,179` which all validate `>= 0xFFFF_8000_0000_0000`.
- **影响:** on any offset mismatch (the 0x050/0x060/0x070 fork, or a future build) the chain reads garbage pointers; without a canonicality guard the blind writes `0` to a wild kernel VA → bugcheck instead of a clean error.
- **修复:** add `if guid_entry < 0xFFFF_8000_0000_0000 { return Err(...) }` after `:235` and the same for `prov_block_kva` after `:244`.

### [MED] NEW-K13 — `scan_all_known` returns Process's RVA under the Thread key; `resolve_offsets` passes identical ranges
- **位置:** `crates/operator-kernelsdk/src/pattern_scan.rs:217-237` (admission at `:216`), consumed at `win/mod.rs:364-366`
- **已核验:** `PSP_CREATE_THREAD_NOTIFY_ROUTINE` uses the identical `4C 8D 35` pattern as Process (`pattern_scan.rs:177-181`). `scan_all_known` calls unfiltered `resolve_rva` for both (`:233`), which returns the **first** match — so the map entry `"PspCreateThreadNotifyRoutine"` holds the Process array's RVA. `resolve_offsets` then does:
  ```rust
  let process_kva = resolve_with_range("PspCreateProcessNotifyRoutine", 0x400_000, 0x600_000); // :364
  let thread_kva  = resolve_with_range("PspCreateThreadNotifyRoutine",  0x400_000, 0x600_000); // :365 — SAME range
  ```
  `resolve_with_range` returns the cached (wrong) map value at `:345-347` before ever reaching the range-filtered scan, so the identical range can't disambiguate them.
- **影响:** `thread_kva == process_kva`; `CallbackNeutralizer::neutralize_array(CreateThread)` ret-stubs routines in the *Process* array a second time and leaves the real Thread array untouched. Thread-creation EDR callbacks keep firing.
- **修复:** in `resolve_offsets`, for Thread pass a range *above* Process's resolved RVA (e.g. `process_rva+0x1000 .. 0x600_000`), or drop Thread from the cached map and always resolve it via `resolve_rva_in_range` with an upper bound distinct from Process.

### [LOW] NEW-K14 — `make_immortal` doc comment encodes the wrong PS_PROTECTION value (0x4B vs actual 0x72)
- **位置:** `crates/operator-kernelsdk/src/persistence.rs:183-191`
- **已核验:** the comment claims `bits[6:3]=Signer 0x08, bits[2:0]=Type 0x04, 0x4B = (0x08<<3)|0x04`. But the code uses the named constants from `offsets.rs`: `TYPE_PROTECTED(2) | (SIGNER_WIN_SYSTEM(7) << SIGNER_SHIFT(4))` = `2 | 0x70` = **0x72** — and `SIGNER_WIN_SYSTEM = 7` (not 0x08) per `offsets.rs:337`. The comment's `(0x08<<3)|0x04 = 0x44 ≠ 0x4B` is also internally inconsistent arithmetically. The code is correct (0x72 = the System process's own protection, which `probe_eprocess_offsets:919` scans for); only the comment is wrong.
- **影响:** an operator reading the doc misunderstands the protection byte being applied; 0x4B would be `Signer=App, Type=Protected` — a different (weaker) level.
- **修复:** rewrite the comment to `0x72 = TYPE_PROTECTED(2) | (SIGNER_WIN_SYSTEM(7) << 4)`.

### [LOW] NEW-K15 — `EtwTiBlind::blind` writes a u64 (8 bytes) to the 4-byte `IsEnabled` ULONG
- **位置:** `crates/operator-kernelsdk/src/etwti.rs:261-263` (`kwrite_u64(target, DISABLED)`); field declared ULONG at `:25`
- **已核验:** `_TRACE_ENABLE_INFO.IsEnabled` is a `ULONG` (4 bytes) per the module's own chain doc (`:25`). `blind` calls `krw.kwrite_u64(target, 0)` which writes 8 bytes, zeroing `IsEnabled` *and* the adjacent `Level`(UCHAR)+`Reserved`. The module doc at `:4` calls it a "single DWORD write."
- **影响:** over-write is harmless for _TRACE_ENABLE_INFO (zeroing Level/Reserved is benign), but it contradicts the documented contract and would corrupt a struct where the +4 field is meaningful.
- **修复:** `krw.kwrite(target, &[0u8;4])` (or add `kwrite_u32`).

### [LOW] NEW-K16 — `LoadedDriver::Drop` deliberately does not unload → abnormal exit leaves durable registry+driver IOC
- **位置:** `crates/operator-kernelsdk/src/win/driver_load.rs:162-167`
- **已核验:**
  ```rust
  impl Drop for LoadedDriver {
      fn drop(&mut self) {
          // Don't auto-unload on drop — the operator may want the driver to stay
          // loaded across multiple operations. Explicit unload() is the cleanup path.
      }
  }
  ```
  If the operator process panics / is killed / Ctrl-C'd without calling `unload()`, the service key under `HKLM\…\Services\<svc>` and the loaded driver both persist.
- **影响:** durable forensic residue (registry service key + a loaded vulnerable driver = Sysmon EID 6 + blocklist signature) on any non-graceful exit. The very scenario an operator hits when something goes wrong is the one that leaves the loudest footprint.
- **修复:** make auto-unload-on-drop configurable (default ON for short-lived CLI runs; OFF for the daemon's long session), or install a panic/ctrl-c hook that calls `unload()`.

### [LOW] NEW-K17 — cfg bitmap set is a non-atomic read-modify-write (lost-update race)
- **位置:** `crates/operator-kernelsdk/src/cfg.rs:101-114`
- **已核验:** `mark_cfg_valid` does `kread(byte) → buf[0] |= 1<<bit → kwrite(byte)` with no interlock between the read and the write.
- **影响:** if another CPU/thread flips a different bit in the same byte between the read and write, that change is clobbered. The CFG bitmap is effectively read-only post-init so practical risk is low, but it's a correctness hazard if anything (including another `mark_cfg_valid` call on a nearby address) races.
- **修复:** use a cmpxchg loop on the byte, or accept the race with a documented note.

### [LOW] NEW-K18 — `cfg-bypass` CLI mixes raw user-mode pointer deref with the kernel primitive for one operation
- **位置:** `crates/operator-kernel-cli/src/main.rs:347-355` (user-mode `*(` derefs) then `:372,380` (`tier.rw.kread/kwrite`)
- **已核验:** the command reads `LdrSystemDllInitBlock` and the bitmap pointer via `unsafe { *(init_addr as *const u32) }` / `*((init_addr + cfg_off) as *const usize)` (raw user-mode derefs in the operator process), then reads/writes the bitmap byte through `tier.rw` (the KslD/BYOVD *kernel* primitive) at a user-mode VA. It functions only because DeviceIoControl runs in the caller's process context so the user-mode VA happens to be mapped.
- **影响:** fragile coupling — the read path and write path use different mechanisms for the same logical object; on a primitive that does NOT inherit caller context (e.g. a DMA/PCILeech `KernelRw`) the user-mode-VA `kread` returns garbage and the wrong bit gets touched. Also duplicates `cfg.rs` logic instead of calling `locate_cfg_bitmap`/`mark_cfg_valid`.
- **修复:** route through `cfg::locate_cfg_bitmap` + `mark_cfg_valid` (which already use `krw` consistently), or do the entire op in user mode.

### [LOW] NEW-K19 — `probe_eprocess_offsets` takes the first qword==4 as the PID offset (false-positive risk)
- **位置:** `crates/operator-kernelsdk/src/offsets.rs:864-871`
- **已核验:**
  ```rust
  for off in (0..0x600).step_by(8) {
      let val = krw.kread_u64(system_eprocess_kva + off)?;
      if val == 4 { pid_offset = Some(off); break; }   // first match wins
  }
  ```
  The System EPROCESS has many qword fields; any field == 4 (a small count, an index, padding) before the real `UniqueProcessId` (~0x2e0–0x440) is taken as the PID offset. No cross-check that the chosen offset is the real PID field. (The Links-Flink canonical check at `:881` catches gross errors but not a plausible early false-positive.) Same single-invariant weakness for the 0x72 protection-byte scan (`:913-923`).
- **影响:** only the Layer-2 fallback for *unknown* builds (table hit short-circuits at `:978`), so practical exposure is novel builds. A misfired PID offset cascades into wrong Token/SignatureLevel/Protection offsets → bugcheck on first use.
- **修复:** add a second invariant (e.g. verify the recovered PID offset also yields the expected Links self-reference, or cross-check ImageFileName offset is in the documented window relative to PID).

### [LOW] NEW-K20 — `probe_eprocess_offsets` computes a `_scan_limit` it never uses
- **位置:** `crates/operator-kernelsdk/src/offsets.rs:861`
- **已核验:** `let _scan_limit = system_eprocess_kva + EPROCESS_SCAN_LIMIT;` — prefixed `_`, never read. The actual scans use raw literals `0..0x600` (`:865`), `links_offset+16..0x600` (`:898`), `image_name_offset+16..0xA00` (`:913`), and the bound check at `:889` uses `EPROCESS_SCAN_LIMIT`. The intended single safety bound is dead.
- **影响:** cosmetic / maintainability; the per-scan literals happen to be within `0x1000`.
- **修复:** drive all scan ceilings from `EPROCESS_SCAN_LIMIT` and drop the dead binding.

---

## 2. 已验证干净的区域 (verified-clean areas, with evidence)

- **pagewalk correctness (`pagewalk.rs:50-111`)** — P-bit checks are correct at all four levels (`& 1 == 0` at `:58,69,85,101`). Large-page masks verified by hand: 1GB page `0x000F_FFFF_C000_0000 | va&0x3FFF_FFFF` (`:76`) = entry[51:30]|va[29:0] ✓; 2MB page `0x000F_FFFF_FFE0_0000 | va&0x001F_FFFF` (`:92`) = entry[51:21]|va[20:0] ✓; 4KB `0x000F_FFFF_FFFF_F000 | va&0xFFF` (`:108`) ✓. The PFN mask `0x000F_FFFF_FFFF_F000` correctly limits intermediate bases to bits 12–51 (MAXPHYADDR=52). `checked_add` is present on the final PA (`:110`). The two `win/` shims (`win/pagewalk.rs`, `win/pattern_scan.rs`) are clean 2-line re-exports — no duplicate logic to drift.

- **`win/resolve.rs` (`:44-103`)** — sound: stack-bounded NUL-termination buffers (`:48-55`, `:81-82`, `:95-97`) with `min(len, cap-1)` copies; `GetModuleHandleA`→`LoadLibraryA` fallback for not-yet-mapped DLLs (`:59-68`); null-check on both `GetProcAddress` results. `extern "system"` block (`:21-25`) declares the three Win32 imports directly. `transmute_copy<*mut c_void, T>` is the standard fn-ptr cast pattern.

- **`win/va_rw.rs` (`:52-92`)** — both `kread` and `kwrite` correctly chunk at 4KB page boundaries and **re-translate per page** (`:64,85`), avoiding the cross-page physical-contiguity bug the comment at `:54-56` warns about. `PhysReadError→KrwError` mapping is exhaustive (`:41-49`). Send/Sync impls are sound (`P: Send+Sync`).

- **`win/kernel_base.rs` (`:70-250`)** — `RtlProcessModuleInformation` is exactly 296 bytes (8+8+8+4+4+2+2+2+2+256), matching `ENTRY_SIZE`. `STATUS_INFO_LENGTH_MISMATCH` retry with exact `ret_len+0x1000` (`:93-108`). Module[0] read is bounds-checked (`:132-136`); `module_info_by_name` breaks on OOB (`:227`) and `ends_with_ci` is a correct case-insensitive tail match (`:215-224`). Handles the Win11 24H2 zeroed-ImageBase case explicitly (`:141-145,234-239`).

- **`offsets::for_build` (`offsets.rs:299-310`)** — **correctly refuses to floor-match**: exact → patch-equivalent allow-list → `None`. The patch-equivalent table (`:275-296`) is an explicit allow-list of known-binary-identical builds (19042→19041 etc.), not a blind floor. This is the right design and the ETW module (NEW-K9) should adopt it.

- **BYOVD partial-write handling (`byovd.rs:296-364`)** — `kread`/`kwrite` return `KrwError::Partial { ok: i }` on mid-stream IOCTL failure (`:326,359`), correctly reporting bytes completed. `open` validates the handle against both null and `INVALID_HANDLE_VALUE` (`:265`) and NUL-terminates the device path into an owned `Vec<u16>` (`:248-253`) — fixing the prior single-backslash bug documented at `:129-132`. `Drop` resolves+calls `CloseHandle` best-effort (`:285-294`).

- **BYOVD driver embedding / signing** — **no `include_bytes!` / embedded `.sys` blobs anywhere** in `operator-kernelsdk` (grep-verified). Drivers are loaded from disk by the operator (`driver_load.rs:5`, `examples/bootstrap_test.rs:71`). The `byovd_drivers/` catalog (`shield`, `wdtkernel`, `rtc64`, `iqvw64e`) carries only IOCTL codes + device paths + struct-layout docs — no binary driver data. Signing is the *driver vendor's* existing signature (DigiCert/WHQL/Microsoft); the framework signs nothing. `blocklist_status()` on each driver honestly reports blocklist state. This is the correct attribution posture (the operator binary is not itself a driver-dropping smoking gun).

- **`win/mod.rs` bootstrap orchestration (`:87-213`)** — `bootstrap_chain` (KslD→BYOVD) and `bootstrap_byovd_with` clean up correctly on failure: device-open failure unloads the just-loaded driver before propagating `Err(NoPrimitive)` (`:177-183`); `blind_etw_ti_full` unloads on blind failure (`:208-211`). `resolve_offsets` degrades gracefully (failed fields → 0, checkable via `notify_arrays_resolved`).

- **KslD `kread`/`kwrite` (`ksld.rs:396-474`)** — chunked at 0x1000 (`:405,445`), partial-error reporting via `KrwError::Partial { ok: offset }` (`:427,467`). Device-open tries direct names then an opt-in `QueryDosDeviceW` enumeration that is **off by default** (`KSLD_SCAN_DEVICES`, `:342-345`) with an explicit note that enumeration is a behavioral IOC (`:339-341`). `Drop` closes the handle (`:387-393`).

- **`WfpSilenceGuard` RAII (`netsec.rs:114-189`)** — the *session-scoping* design is sound: filters live only as long as the guard, `Drop` closes the BFE session which auto-removes them (`:132-149`), atomic install (a mid-install failure drops the guard → partial filters removed, `:266-267`), idempotent close (`:137`). (The *content* of the filters is broken — NEW-K1 — but the lifecycle plumbing is correct.)

- **`persistence.rs` unlink/strip validation** — `ProcessHider::unlink` validates link_kva, flink, blink all canonical kernel VAs before writing (`:88,95`); self-loops the victim to avoid dangling pointers (`:105-106`). `PplStripper::strip_protection` validates `eprocess_kva` canonical (`:147`) and writes only single bytes. `find_eprocess` is shared across all kits.

- **Operator CLI build detection + offset sourcing (`main.rs:47-73`)** — build number comes from `RtlGetVersion` at runtime (`detect_build`, `:405-446`), never hardcoded; offsets come from the build table with a clean `exit(2)` on unknown build (`:51-59`) and non-fatal ETW degradation (`:62-73`). No baked-in build constant.

---

## 3. Summary table

| ID | Sev | File:line | One-liner | Baseline |
|----|-----|-----------|-----------|----------|
| MED-10 | MED | pagewalk.rs:107-111 | No RAM/MMIO validation on translated PA | **CONFIRMED** |
| LOW-10 | LOW | netsec.rs:670-716 | Predictable `nyx_freeze_<pid>.dmp` path | **CONFIRMED** |
| — | — | (recount) | "72 unwraps" → actually 105 (98 sdk + 7 cli); 0 panic-capable in prod | **STALE count; verdict holds** |
| NEW-K1 | HIGH | netsec.rs:314-335 | WFP silence blocks ALL host IPv4, ignores PID | new |
| NEW-K2 | HIGH | netsec.rs:807-922 | choke ignores PID (global throttle) + wrong QOSCreateHandle arity | new |
| NEW-K3 | MED | netsec.rs:719-755 | Full EDR memory dump left on disk, never deleted | new |
| NEW-K4 | MED | telemetry.rs:76-110 | neutralize ret-stubs nt! dispatcher (slot 0) | new |
| NEW-K5 | MED | telemetry.rs:270-299 | detach_edr unlinks ALL minifilters | new |
| NEW-K6 | MED | byovd.rs:425-447 | djb2-only export match → collision → wrong KVA | new |
| NEW-K7 | MED | main.rs:470-513 | Daemon: no-auth local kernel-R/W surface | new |
| NEW-K8 | MED | main.rs:540 | Daemon: predictable `lsass_{pid}.dmp` in CWD | new |
| NEW-K9 | MED | etwti.rs:124-175 | ETW for_build floor-matches (contradicts own warning) | new |
| NEW-K10 | MED | cfg.rs:204-231 | Export-name truncation → prefix false-match | new |
| NEW-K11 | MED | byovd.rs:297-363 | 1 byte/IOCTL → 1M IOCTLs for 1 MiB LSASS read | new |
| NEW-K12 | MED | etwti.rs:230-254 | No canonicality check on chain pointers | new |
| NEW-K13 | MED | pattern_scan.rs:216 + mod.rs:364-366 | Thread array resolves to Process array (same pattern+range) | new |
| NEW-K14 | LOW | persistence.rs:183-191 | make_immortal comment says 0x4B, code makes 0x72 | new |
| NEW-K15 | LOW | etwti.rs:261-263 | blind writes u64 to 4-byte IsEnabled | new |
| NEW-K16 | LOW | driver_load.rs:162-167 | Drop doesn't unload → durable IOC on abnormal exit | new |
| NEW-K17 | LOW | cfg.rs:101-114 | Non-atomic RMW on CFG bitmap byte | new |
| NEW-K18 | LOW | main.rs:347-380 | cfg-bypass mixes user-mode deref + kernel primitive | new |
| NEW-K19 | LOW | offsets.rs:864-871 | Probe takes first qword==4 as PID offset | new |
| NEW-K20 | LOW | offsets.rs:861 | Dead `_scan_limit` binding | new |

**Highest-priority fixes:** NEW-K1 + NEW-K2 (false "surgical EDR silence" capabilities that would black out/throttle the whole host on first use), NEW-K4 (neutralize bugchecks via slot-0 dispatcher), NEW-K6 (hash-collision → kernel VA → BSOD, trivially fixable with a byte compare), NEW-K7/K8 (daemon local privilege-escalation surface).
