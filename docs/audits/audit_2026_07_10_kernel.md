# Kernel-Tier Audit — `operator-kernelsdk` + `operator-kernel-cli`

**Scope:** `crates/operator-kernelsdk/src/` (byovd.rs, cfg.rs, etw_deception.rs, etwti.rs, lib.rs, netsec.rs, offsets.rs, pagewalk.rs, pattern_scan.rs, persistence.rs, telemetry.rs) + `src/win/` (driver_load.rs, kernel_base.rs, ksld.rs, mod.rs, pagewalk.rs, pattern_scan.rs, resolve.rs, va_rw.rs) + `src/byovd_drivers/` (mod.rs, shield.rs, rtc64.rs, iqvw64e.rs, wdtkernel.rs) + `crates/operator-kernel-cli/src/` (main.rs + `bin/{cfg-write,find-bitmap,probe-offsets,probe2}.rs`).
**Reviewer:** AuditKernel · **Date:** 2026-07-10 · **Method:** line-by-line static review of every file; `git diff` on every touched file; each claim grounded in observed code with exact line numbers.

---

## Executive summary

The only kernel-tier file touched by the fix-in-progress is **`netsec.rs`** (`git diff --stat -- crates/operator-kernelsdk/` shows exactly 1 file, +49/-42). The fix:

- **HIGH-K1 (WFP nuclear block) — FIXED (fail-closed).** `block_outbound_for_pid` now refuses to build a `num_filter_conditions=0` filter and returns `Err`, which propagates through `silence_edr`. The fix is correct and honest: it explicitly documents that a real fix needs PID→image-path resolution + `FWPM_CONDITION_ALE_APP_ID`, and that shipping the nuke filter would black out the host.
- **HIGH-K2 (QOS FFI arity) — PARTIALLY FIXED.** The `QOSCreateHandle` arity is corrected (now 2 params with a real `QOS_VERSION {1,0}` struct). **But the `pid` is still ignored** (host-wide throttle, now documented as a known limitation). The doc string at the trait/docs level still calls it "Lowest-noise option" without surfacing the host-wide caveat. Functionally safer than before (no more stack-frame corruption) but still a misleadingly-named capability.

Every other 07-08 finding (K3–K20, MED-10, LOW-10) is **STILL PRESENT** — none of those files were touched.

I found **3 NEW issues** this pass:

- **NEW-K21 (HIGH)** — `etw_deception.rs::forge_process_create` builds a structurally malformed `EVENT_HEADER` (wrong Size width, swapped ThreadId/ProcessId, missing ActivityId, wrong total size = 64 vs real 80). The unit test entrenches the bug by asserting the wrong offsets. Forged events will be rejected or mis-parsed by any EDR that consumes them — the capability is a no-op at best, an attribution leak at worst.
- **NEW-K22 (MED)** — The `VulnDriverIoctl` trait is too thin to correctly model drivers whose IOCTL protocol differs from RTCore64. `iqvw64e` (addr@0x00, different result layout) and `WDTKernel` (MmMapIoSpace-based, different struct) are routed through the RTCore64-shaped `ByovdDriver` byte-loop, which assumes size@0x18/data@0x1C/result@0x1C. Only RTCore64 (and structurally-identical drivers) work correctly.
- **NEW-K23 (LOW)** — `freeze_edr_coma` header doc (lines 592-593) says "Do NOT close the dump file handle — keeping it open maintains the coma", but the code at lines 754-755 **does** close both handles. The doc and code contradict each other on whether handle-closure ends the coma.

---

## 1. Re-verification of 07-08 findings

### [HIGH] NEW-K1 — WFP `silence_edr` nukes host outbound → **FIXED (fail-closed)**
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:263` (call site) and `:326-335` (filter builder)
- **状态:** **FIXED**
- **已核验:** `git diff` shows the old `fn block_outbound_for_pid(pid) -> Self` (which set `num_filter_conditions = 0`) replaced with `fn block_outbound_for_pid(pid) -> Result<Self, KitError>` that **unconditionally returns `Err`**:
  ```rust
  fn block_outbound_for_pid(pid: u32) -> Result<Self, KitError> {   // :326
      let _ = pid;
      Err(KitError::Other(
          "WFP PID-based outbound block not implemented: refusing to install a filter with \
           num_filter_conditions=0 (which matches ALL outbound IPv4 traffic, not just the \
           target PID). Resolve pid to image-path and condition on \
           FWPM_CONDITION_ALE_APP_ID before enabling this."
               .into(),
      ))
  }
  ```
  The call site at `:263` now propagates via `?`: `let filter = FwpmFilter0::block_outbound_for_pid(rule.pid)?;`. The `WfpSilenceGuard` RAII is preserved (the atomic-install contract holds: a mid-install `?`-return drops the guard → session closes → partial filters removed, `:266-267`). The doc comment (`:313-325`) honestly explains *why* — WFP cannot filter on PID, the correct condition is `FWPM_CONDITION_ALE_APP_ID`, and the needed pid→image-path resolution (`NtQuerySystemInformation`) isn't wired yet.
- **影响:** `silence_edr` now fails loudly instead of cutting the host off the network. The "surgical EDR telemetry silence" capability is **correctly disabled** until a real PID→AppId filter is implemented. Operators get an error rather than a self-DoS.
- **残留风险 (residual):** the capability is still advertised at the trait level (`WfpKit::silence_edr` doc at `:42-53`, `lib.rs`) as a working silencer. An operator who hasn't read the new error text will be surprised when it fails. Consider renaming or adding a `cfg!(feature = "wfp_appid")` gate so the failure is a compile-time signal, not a runtime one. Also: V6 layer twin is still absent (only `LAYER_ALE_AUTH_CONNECT_V4` is even declared), so even a future AppId fix would leave IPv6 EDR telemetry unaffected.

### [HIGH] NEW-K2 — `choke_edr_qos` wrong FFI arity + ignores PID → **PARTIALLY FIXED**
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:807-938`
- **状态:** **PARTIALLY FIXED** — FFI arity corrected; PID still ignored (now documented)
- **已核验:**
  - **FFI arity FIXED.** `git diff` shows the old 3-param `QOSCreateHandleFn` (`*const u16, u32, *mut *mut c_void`) replaced by a correct 2-param signature with a real `QOS_VERSION` struct:
    ```rust
    #[repr(C)] struct QOS_VERSION { major: u32, minor: u32 }   // :818-822
    type QOSCreateHandleFn = unsafe extern "system" fn(
        *const QOS_VERSION, // Version ({1,0} = QOS_VERSION_1)
        *mut *mut c_void,   // QosHandle (OUT)
    ) -> i32;                                                 // :823-826
    ```
    The call at `:883-884` now passes `QOS_VERSION { major: 1, minor: 0 }` and 2 args. This removes the stack/register-corruption UB.
  - **PID STILL IGNORED.** Line 898: `let _ = pid;`. `add_filter` (`:905-911`) and `set_flow` (`:918-929`) still call with `core::ptr::null()` AppId = "apply to all flows". The function is still a **host-wide throttle**. The inline comment at `:891-898` now honestly documents this: *"treat `choke_edr_qos` as a HOST-WIDE throttle, not a surgical per-EDR one"*.
  - **Doc-level caveat MISSING.** The `§2.5b` section header (`:776-789`) still claims *"Lowest-noise option. User-mode, admin required"* and *"the qWave approach as it's more portable"*; the doc string at `:799` still says *"Lowest-noise option — no WFP events, no packet-drop traces"* without the host-wide caveat. Only the buried inline comment surfaces the limitation.
  - `add_filter`/`set_flow` return values are still discarded (`let _ = …` at `:905,918`) — failure is invisible.
- **影响:** the QOS path no longer corrupts state on every call (good), but calling `NeutralizeMethod::Choke` (dispatched at `:573`) still throttles **every** flow on the host — including the operator's own C2. The misleading section header means an operator reading the docs (not the inline comment) will believe it's surgical.
- **修复:** (a) either implement real per-process QoS binding (`QOS_FILTER_CONFIG` keyed to the EDR's flows), or mark the posture `UnsupportedPosture` like K1; (b) propagate the host-wide caveat into the `§2.5b` header and the `choke_edr_qos` doc string (not just the inline comment); (c) check `add_filter`/`set_flow` return values.

### [MED] NEW-K3 — `freeze_edr_coma` full EDR dump never deleted → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:614-767` (no `DeleteFileW` anywhere in the function)
- **状态:** **STILL PRESENT**
- **已核验:** the function writes `\\?\C:\Windows\Temp\nyx_freeze_<pid>.dmp` via `CreateFileW(CREATE_ALWAYS)` (`:718-729`), `MiniDumpWriteDump(..., MINIDUMP_WITH_FULL_MEMORY, …)` writes the full EDR address space (`:738-748`), then both handles are closed (`:754-755`). **No `DeleteFileW` exists anywhere in the function** (grep-confirmed). A full-memory dump of an EDR process — one of the highest-value forensic artifacts — persists on disk indefinitely.
- **额外发现 (NEW-K23, see §2):** the header doc at `:592-593` says *"Do NOT close the dump file handle — keeping it open maintains the coma"*, directly contradicting the code at `:754-755` which closes both handles. The doc and code disagree on whether handle-closure terminates the WER coma.
- **影响:** durable forensic artifact (full EDR memory including detection logic + any operator IOCs dropped into the EDR heap) + predictable path (`nyx_freeze_*.dmp`, LOW-10) + disk hazard (GBs).

### [MED] NEW-K4 / NEW-K3(07-08) — `CallbackNeutralizer::neutralize` ret-stubs nt! dispatcher (slot 0) → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/telemetry.rs:76-110` (`neutralize_array`)
- **状态:** **STILL PRESENT** (the fix was applied to `repurpose` at `:159-196` but **NOT** ported to `neutralize_array`)
- **已核验:** `neutralize_array` guards only on `occupied`, `ctx != 0`, `routine != 0`, and `routine >= 0xFFFF_8000_0000_0000` (`:82,86,93,101`). It then unconditionally writes `RET_STUB` (`:106`). There is **no ntoskrnl-range skip and no slot-0 skip**. Contrast `repurpose` (`:159-196`), which now correctly implements both the range-based skip (`skip_ntoskrnl`, `:159-160`, `:184-190`) and the fallback slot-0 skip (`:191-196`). The module doc at `:133-136` explicitly warns: *"slot[0] of each Ps*NotifyRoutine array is the nt! internal dispatcher — overwriting it causes system instability and PatchGuard detection."*
  The unit test at `:355-378` confirms the bug: it occupies slot 0 (`krw.set_u64(array_kva + 0*8, ctx_a as u64 | 0x1)` at `:364`) and asserts the neutralizer ret-stubs it (`assert_eq!(n, 2)` at `:378` — both slot 0 and slot 3). The test would **fail** if the fix were applied, which is why the fix wasn't applied here.
- **影响:** `neutralize()` (the trait method an operator calls for "neutralize all three arrays") ret-stubs the kernel's own PsNotify dispatcher → broken callback dispatch + near-certain PatchGuard bugcheck. The asymmetry between `neutralize` (unsafe) and `repurpose` (safe) is exactly backwards: `repurpose` is the HVCI-safe variant but got the safety logic, while `neutralize` — the more dangerous code-write path — did not.
- **修复:** port the `skip_ntoskrnl`/slot-0 logic from `repurpose` (`:159-196`) into `neutralize_array`. Update the test to assert slot 0 is skipped.

### [MED] NEW-K5(07-08) / K5 here — `detach_edr` unlinks ALL minifilters → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/telemetry.rs:270-299`
- **状态:** **STILL PRESENT**
- **已核验:** the walk unlinks every entry with no name filter: `self.unlink_filter(krw, filter_base)?` at `:291` is unconditional inside `while cur != 0 && cur != list_head && unlinked < 256` (`:286`). The doc at `:260-263` still concedes *"nuclear option: detaches ALL minifilters, including non-EDR ones."* This is the method the CLI `detach-minifilter` command and the daemon `detach-minifilter` op call (`main.rs:577`).
- **影响:** rips out Defender, third-party AV, storage filter drivers. System destabilization + massive IOC.

### [MED] NEW-K6(07-08) — `resolve_kernel_symbol` djb2-only match → collision → BSOD → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/byovd.rs:401-450` (hash compare at `:444`)
- **状态:** **STILL PRESENT**
- **已核验:** the export walk hashes each name (`:429-443`) and returns the first whose hash equals `djb2(name)` (`:444-447`) with **no byte comparison**:
  ```rust
  if h == target_hash {                          // :444
      let ord = read_u16_le(ntoskrnl_image, ordinals_rva + i * 2)? as usize;
      return read_u32_le(ntoskrnl_image, funcs_rva + ord * 4);   // :445-446
  }
  ```
  The name bytes are read into `ntoskrnl_image[p]` (`:435`) but only hashed, never compared against `name`. `djb2` is non-cryptographic with known collisions. Used by `win::resolve_offsets` to resolve `EtwThreatIntProvRegHandle` — a collision returns the wrong RVA → `EtwTiBlind` writes `0` to an arbitrary kernel address → bugcheck. Operator-side (no stealth constraint), so a byte compare is free.
- **修复:** after the hash matches, compare `name == ntoskrnl_image[name_rva..name_rva+name.len()]` (and verify the next byte is NUL) before returning.

### [MED] NEW-K7(07-08) — daemon: unauthenticated localhost kernel-R/W surface → **STILL PRESENT**
- **位置:** `crates/operator-kernel-cli/src/main.rs:470-596`
- **状态:** **STILL PRESENT** (`operator-kernel-cli` has zero uncommitted changes)
- **已核验:** `TcpListener::bind("127.0.0.1:{port}")` (`:470-471`) accepts connections with **no auth token, no ACL, no peer check**. The loop (`:482-513`) reads newline-delimited lines and dispatches `dump-lsass` (`:530-553`), `blind-etw` (`:555-564`), `hide` (`:565-574`), `detach-minifilter` (`:575-584`) — all of which drive the live kernel primitive. Any local process can connect and post `{"op":"dump-lsass","pid":684}`.
- **影响:** local privilege escalation / abuse. A low-priv process (or a Defender scan payload) connects and dumps LSASS, blinds ETW-TI, or hides an arbitrary PID, all as the daemon's admin identity.

### [MED] NEW-K8(07-08) — daemon: predictable `lsass_{pid}.dmp` in CWD → **STILL PRESENT**
- **位置:** `crates/operator-kernel-cli/src/main.rs:540-541`
- **状态:** **STILL PRESENT**
- **已核验:** `let path = format!("lsass_{pid}.dmp");` (`:540`) then `std::fs::write(&path, &dump)` (`:541`). Written relative to the daemon's CWD, predictable name, no `O_NOFOLLOW`/exclusive-create. Compounds NEW-K7: an unauthenticated local attacker pre-creates a symlink `lsass_<pid>.dmp → C:\Windows\System32\somelib.dll`; the daemon's `std::fs::write` (truncate-on-open) clobbers the target with minidump bytes as the daemon's admin identity → arbitrary file overwrite.

### [MED] NEW-K9(07-08) — ETW-TI `for_build` floor-matches (contradicts own "NEVER floor-match" warning) → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/etwti.rs:124-175` (`floor_match` at `:160-175`)
- **状态:** **STILL PRESENT**
- **已核验:** `for_build`'s default arm calls `Self::floor_match(build)` (`:154`), which maps any `build >= 26100` → 26100, `>= 22621` → 22621, etc. (`:160-174`). This directly contradicts `offsets.rs::for_build` (`:299-310`) which returns `None` for unknown builds with *"Does NOT floor-match. A blind floor-match silently gambles the layout is unchanged — wrong on every EPROCESS restructuring → bugcheck."* The ETW module's own header (`:80-81`) repeats: *"NEVER hardcode a single offset across builds."* The `_ETW_GUID_ENTRY::ProviderEnableInfo` offset has already moved `0x050→0x060→0x070` across recent builds.
- **影响:** a future Windows build that restructures `ProviderEnableInfo` will be floor-matched to the last-known offset → `blind()` writes `0` to the wrong kernel field → corruption + no blind or bugcheck.

### [MED] NEW-K10(07-08) — cfg.rs export-name truncation → prefix false-match → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/cfg.rs:204-234` (truncation at `:215-217`)
- **状态:** **STILL PRESENT**
- **已核验:** `let cmp_len = name_bytes.len().min(63);` (`:215`) reads only `cmp_len` bytes (`:216`), then byte-compares against the search name. If a real export is longer than the search name but shares its prefix, `cmp == name_bytes` → false exact match → wrong RVA. Harmless for the current single caller (`LdrSystemDllInitBlock`, no longer-prefix sibling) but latent for any future short-name caller.

### [MED] NEW-K11(07-08) — BYOVD 1 byte/IOCTL → ~1M IOCTLs for 1 MiB LSASS read → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/byovd.rs:296-363`
- **状态:** **STILL PRESENT**
- **已核验:** `kread` (`:305`) loops `dst.iter_mut().enumerate()` one byte per IOCTL, writes `1u32` at the size field (`:310`), reads one byte at `0x1C` (`:329`). Same for `kwrite` (`:340`, writes `in_byte as u32` at `:344`). RTCore64 supports `size ∈ {1,2,4}` but the loop hardcodes 1. `KernelLsassReader::dump_lsass_with_base` reads `0x10_0000` (1 MiB) via this path. **This now also applies to Shield, WDTKernel, and iqvw64e** (all route through the same `ByovdDriver` loop — see NEW-K22). ~1M kernel IOCTLs per LSASS dump: minutes of wall time + enormous IOCTL telemetry burst.
- **修复:** chunk at the driver's max width (4 bytes for RTCore64); coalesce aligned runs.

### [MED] NEW-K12(07-08) — ETW-TI chain no canonicality check on intermediate pointers → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/etwti.rs:230-254`
- **状态:** **STILL PRESENT**
- **已核验:** `resolve_is_enabled_kva` checks `guid_entry == 0` (`:236`) and `prov_block_kva == 0` (`:245`) only. A non-zero but user-mode / non-canonical value passes both guards and the final `kwrite_u64(target, 0)` writes to a wild address. Contrast `persistence.rs:88,95,147,204` and `telemetry.rs:101,172,179` which all validate `>= 0xFFFF_8000_0000_0000`.

### [MED] NEW-K13(07-08) — Thread array resolves to Process array (same pattern + range) → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/pattern_scan.rs:217-237` (admission at `:216`); consumed at `win/mod.rs:364-366`
- **状态:** **STILL PRESENT**
- **已核验:** `PSP_CREATE_THREAD_NOTIFY_ROUTINE` (`:177-181`) uses the identical `4C 8D 35` pattern as Process. `scan_all_known` calls unfiltered `resolve_rva` for both (`:233`), returning the first match. The doc at `:216` admits it. `resolve_offsets` then passes identical ranges: `resolve_with_range("PspCreateProcessNotifyRoutine", 0x400_000, 0x600_000)` (`:364`) and `resolve_with_range("PspCreateThreadNotifyRoutine", 0x400_000, 0x600_000)` (`:365`) — the cached map value is returned at `:345-347` before the range-filtered scan can disambiguate. Result: `thread_kva == process_kva`; `neutralize_array(CreateThread)` ret-stubs the Process array twice and leaves the real Thread array untouched.

### [LOW] NEW-K14(07-08) — `make_immortal` comment encodes wrong PS_PROTECTION value → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/persistence.rs:183-191`
- **状态:** **STILL PRESENT**
- **已核验:** comment claims `bits[6:3]=Signer 0x08, bits[2:0]=Type 0x04, 0x4B = (0x08<<3)|0x04` (`:189-191`). But the code uses `TYPE_PROTECTED(2) | (SIGNER_WIN_SYSTEM(7) << SIGNER_SHIFT(4))` (`:212-213`) = `2 | 0x70` = **0x72**. `offsets.rs:337` confirms `SIGNER_WIN_SYSTEM = 7` (not 0x08), and `:341` confirms `SIGNER_SHIFT = 4` (not 3). The comment's arithmetic `(0x08<<3)|0x04 = 0x44 ≠ 0x4B` is also internally inconsistent. Code is correct (0x72); comment is wrong on three counts.

### [LOW] NEW-K15(07-08) — ETW-TI `blind` writes u64 to 4-byte IsEnabled → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/etwti.rs:261-263`
- **状态:** **STILL PRESENT**
- **已核验:** `blind` calls `krw.kwrite_u64(target, DISABLED)` (`:263`), writing 8 bytes, but `_TRACE_ENABLE_INFO.IsEnabled` is a `ULONG` (4 bytes, documented at `:25`). Zeros `IsEnabled` + adjacent `Level`(UCHAR)+`Reserved`. Benign for this struct but contradicts the "single DWORD write" contract at `:4`.

### [LOW] NEW-K16(07-08) — `LoadedDriver::Drop` doesn't unload → durable IOC → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/win/driver_load.rs:162-167`
- **状态:** **STILL PRESENT**
- **已核验:** `Drop` is an empty body (`:163-166`). On panic/Ctrl-C, the service key under `HKLM\…\Services\<svc>` + loaded driver persist (Sysmon EID 6 + blocklist signature).

### [LOW] NEW-K17(07-08) — CFG bitmap non-atomic RMW → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/cfg.rs:101-114`
- **状态:** **STILL PRESENT**
- **已核验:** `mark_cfg_valid` does `kread(byte) → buf[0] |= 1<<bit → kwrite(byte)` (`:102,107,114`) with no interlock. Lost-update race if another CPU flips a bit in the same byte between read and write.

### [LOW] NEW-K18(07-08) — `cfg-bypass` CLI mixes user-mode deref + kernel primitive → **STILL PRESENT**
- **位置:** `crates/operator-kernel-cli/src/main.rs:347-380`
- **状态:** **STILL PRESENT** (CLI unchanged)
- **已核验:** reads `LdrSystemDllInitBlock` via raw user-mode `*(init_addr as *const u32)` then reads/writes the bitmap byte through `tier.rw` (the kernel primitive) at a user-mode VA. Fragile coupling; duplicates `cfg.rs` logic instead of calling `locate_cfg_bitmap`/`mark_cfg_valid`.

### [LOW] NEW-K19(07-08) — `probe_eprocess_offsets` takes first qword==4 as PID offset → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/offsets.rs:864-871`
- **状态:** **STILL PRESENT**
- **已核验:** `for off in (0..0x600).step_by(8) { if val == 4 { pid_offset = Some(off); break; } }` — first match wins, no cross-check. Only the Layer-2 fallback for unknown builds.

### [LOW] NEW-K20(07-08) — dead `_scan_limit` binding → **STILL PRESENT**
- **位置:** `crates/operator-kernelsdk/src/offsets.rs:861`
- **状态:** **STILL PRESENT**
- **已核验:** `let _scan_limit = system_eprocess_kva + EPROCESS_SCAN_LIMIT;` — prefixed `_`, never read. Scans use raw literals `0..0x600`, `links_offset+16..0x600`, `image_name_offset+16..0xA00`.

### Baseline (07-08) carry-forwards — **STILL PRESENT**

| ID | Sev | 位置 | 状态 |
|----|-----|------|------|
| MED-10 | MED | `pagewalk.rs:107-111` | **STILL PRESENT** — final PA only has `checked_add` (arithmetic overflow guard), no RAM/MMIO validation; intermediate entry PAs at `:56,67,83,99` have no bounds/canonicality check |
| LOW-10 | LOW | `netsec.rs:670-716` | **STILL PRESENT** — `\\?\C:\Windows\Temp\nyx_freeze_<pid>.dmp` deterministic path, comment at `:671` concedes it |

---

## 2. NEW findings (this pass, beyond 07-08 baseline)

### [HIGH] NEW-K21 — `etw_deception::forge_process_create` builds a malformed `EVENT_HEADER` (wrong layout, wrong size)
- **位置:** `crates/operator-kernelsdk/src/etw_deception.rs:156-239` (constants at `:61,88-114`); test entrenching the bug at `:461-496`
- **状态:** NEW (not in 07-08 baseline — that audit did not cover `etw_deception.rs`)
- **已核验:** the real Windows `EVENT_HEADER` (evntprov.h) is **80 bytes (0x50)**:
  ```text
  0x00 USHORT Size; 0x02 USHORT HeaderType; 0x04 USHORT Flags; 0x06 USHORT EventProperty;
  0x08 ULONG ThreadId; 0x0C ULONG ProcessId; 0x10 LONGLONG TimeStamp; 0x18 GUID ProviderId;
  0x28 EVENT_DESCRIPTOR (16B); 0x38 union{KernelTime;ProcessorTime}; 0x3C ULONG UserTime;
  0x40 GUID ActivityId;   // <-- 16 bytes the code omits
  ```
  The code's `EVENT_HEADER_SIZE = 64` (`:61`) is **wrong by 16 bytes** (omits `ActivityId`). Concrete field errors in `forge_process_create`:
  1. **Size as u32 (`:186`):** `buf[0..4].copy_from_slice(&(total_size as u32).to_le_bytes())` writes a 4-byte u32 into the `[Size:u16 | HeaderType:u16]` pair, clobbering `HeaderType` (which must be `EVENT_HEADER_TYPE`).
  2. **ThreadId/ProcessId swapped (`:192-194`):** code writes `parent_pid` to `buf[8..12]` (offset 0x08 = `ThreadId` in the real struct) and `0` to `buf[12..16]` (0x0C = `ProcessId`). The real layout is `ThreadId@0x08, ProcessId@0x0C` — so `parent_pid` lands in `ThreadId` and `ProcessId` is zeroed. An EDR validating the PID will see 0.
  3. **Flags at wrong offset (`:190`):** `buf[6..8]` = offset 0x06 = `EventProperty`, not `Flags` (0x04).
  4. **Missing ActivityId (`:218`):** the buffer stops at offset 64; the 16-byte `ActivityId` (0x40-0x4F) is never written. `HeaderSize` is set to 64 (`:188`), so a parser reading `EVENT_HEADER_SIZE` bytes reads 64 and misses the trailing GUID — or, if it trusts the documented 80-byte layout, reads 16 bytes of UserData as ActivityId.
  5. **Keyword/KernelTime overlap (`:216-218`):** the code writes Keyword at `buf[48..56]` (0x30, correct relative to descriptor@0x28) then KernelTime/UserTime at `buf[56..64]` (0x38, correct). But because the buffer is 64 bytes total and UserData starts at `EVENT_HEADER_SIZE`=64 (`:221`), UserData immediately follows — there is no room for `ActivityId`. The layout is internally consistent only against the (wrong) `EVENT_HEADER_SIZE=64` constant.

  **The test entrenches the bug.** `forge_process_create_builds_correct_buffer` (`:461-496`) asserts:
  - `size = u32::from_le_bytes([buf[0..4])` — reads Size as u32 (matching the buggy write) instead of u16.
  - `pid = u32::from_le_bytes([buf[8..12]); assert_eq!(pid, 100)` — asserts parent_pid is at offset 8 (ThreadId in the real struct), not offset 0x0C.
  - `header_size == EVENT_HEADER_SIZE (64)` — asserts the wrong constant.
  The test passes but validates the wrong layout — a classic "test that passes but doesn't test the real contract."
- **影响:** the entire `EtwDeceiver` capability produces buffers no conformant ETW consumer (including the kernel logger that `NtTraceEvent` feeds) will parse correctly. At best the forged events are silently dropped (the deception is a no-op — EDR detects the frequency anomaly anyway); at worst a malformed `EVENT_TRACE_HEADER` handed to `NtTraceEvent` returns `STATUS_INVALID_PARAMETER` or, depending on the logger, corrupts the session. The `EventFrequencyKeeper` (`:290-439`) correctly computes timing but feeds it into a broken forge path — so the whole Phase-4 deception subsystem is inert.
- **修复:** (a) set `EVENT_HEADER_SIZE = 80` and reserve/zero the `ActivityId` field; (b) write `Size` as u16 at 0x00 and `HeaderType` as u16 at 0x02; (c) put `Flags` at 0x04, `EventProperty` at 0x06; (d) swap the ThreadId(0x08)/ProcessId(0x0C) writes; (e) fix the test to assert the real offsets. Validate against a captured real `EVENT_HEADER` from `EventWrite`.

### [MED] NEW-K22 — `VulnDriverIoctl` trait too thin: non-RTCore64 drivers (iqvw64e, WDTKernel) routed through an RTCore64-shaped byte-loop
- **位置:** `crates/operator-kernelsdk/src/byovd.rs:296-363` (generic loop); trait at the top of `byovd.rs`; drivers in `byovd_drivers/{iqvw64e,wdtkernel,shield,rtc64}.rs`
- **状态:** NEW
- **已核验:** `ByovdDriver::kread`/`kwrite` assume a fixed struct layout: address at `driver.addr_offset()` (`:306,342`), size field at `0x18` (`:310`), data at `0x1C` (`:329,344`), and — critically — that the **read result byte comes back at `op[0x1C]`** (`:329`). This is the RTCore64 layout. The `VulnDriverIoctl` trait only exposes `{device_path, read_ioctl, write_ioctl, addr_offset, blocklist_status}` — it cannot express per-driver struct differences. The driver packs contradict this:
  - **iqvw64e (`iqvw64e.rs:9,26`):** *"address at offset 0x00 (different from RTCore64)"*, `addr_offset() = 0x00`. iqvw64e's real protocol (CVE-2022-24245) is `[u64 mapped_addr][u32 value]` for write and returns the read dword inline — the size@0x18/data@0x1C/result@0x1C fields don't exist in its struct. Feeding it the RTCore64-shaped 48-byte buffer with size=1 at 0x18 is semantically wrong; the read result won't appear at 0x1C.
  - **WDTKernel (`wdtkernel.rs:14-16`):** *"12 IOCTLs for arbitrary physical memory r/w via MmMapIoSpace."* MmMapIoSpace-based drivers use `[u64 phys_addr][u32 size][u8* user_buffer]` — the buffer is a *user pointer* the driver copies into, not an inline result at 0x1C. The doc even says *"standard 48-byte"* but the semantics differ: `kread` here does `op[0x1C]` to fetch the byte, which for WDTKernel reads from the wrong location (the driver wrote into the user buffer pointer, not into the ioctl struct).
  - **Shield (`shield.rs:5-9`):** *"direction (0=write, 1=read) + u64 dst + u64 src + u32 len"* — a single bidirectional IOCTL with a direction byte. The generic loop calls `read_ioctl()` and `write_ioctl()` as if they're separate codes, but Shield returns the *same* code (`0x96102014`) for both (`shield.rs:38-39`), with direction determined by a byte the generic loop never sets. Shield reads/writes will all go one direction.
- **影响:** only **RTCore64** (and a hypothetical structurally-identical driver) works correctly through `ByovdDriver`. iqvw64e, WDTKernel, and Shield will read garbage / write to wrong addresses / silently no-op — and because the loop returns `Ok(())` when `DeviceIoControl` succeeds (the driver accepted the struct, just interpreted it wrong), the failure is **silent**. An operator who selects `NYX_BYOVD=wdtkernel` or `iqvw64e` (`default_driver` at `byovd.rs:460`) gets a primitive that appears to work but corrupts kernel memory or returns wrong data. This is especially dangerous for WDTKernel, which is advertised as *"HVCI-compatible"* and *"preferred for modern targets"* (`wdtkernel.rs:3,11`) — operators will reach for it first on hardened hosts.
- **修复:** either (a) give each driver its own `impl KernelRw` with its real struct layout (Shield already half-implements its own — extend that pattern), or (b) extend `VulnDriverIoctl` with `build_read_op(addr, len) -> Vec<u8>`, `extract_read_byte(&op) -> u8`, `build_write_op(addr, val)`, etc., so each driver controls its own framing. At minimum, add a `works_with_generic_loop() -> bool` flag and have `default_driver()` reject drivers that return false, so an operator doesn't silently get a broken primitive.

### [LOW] NEW-K23 — `freeze_edr_coma` header doc contradicts code on whether handle-closure ends the WER coma
- **位置:** `crates/operator-kernelsdk/src/netsec.rs:592-593` (header doc) vs `:754-755` (code)
- **状态:** NEW
- **已核验:** the `§2.5a` header says:
  ```text
  6. Do NOT close the dump file handle — keeping it open maintains the coma.
     The operator closes it when they want the EDR to recover.       // :592-593
  ```
  But the code does the opposite:
  ```rust
  let _ = unsafe { close_handle(h_process) };   // :754
  let _ = unsafe { close_handle(h_file) };      // :755
  // ... and the comment at :750-753 explains WHY closing is correct:
  // "Keeping the file handle open is a forensic trace (handle-table leak);
  //  we close it here so the operator never leaks a permanent handle."
  ```
  The inline comment (`:750-753`) and the code agree (close both handles); the header doc (`:592-593`) is stale and wrong. They contradict on a load-bearing behavioral question: does the WER coma survive handle closure? If an operator reads the header doc and believes closure ends the coma, they may leave handles open to "preserve" it — creating exactly the handle-table leak the code tries to avoid.
- **影响:** operator confusion about coma persistence; the stale doc could induce a handle leak if taken at face value. Cosmetic-correctness issue but in a high-stress operator-decision path.
- **修复:** delete or rewrite the `§2.5a` step-6 line to match the code: *"Close both handles — the WER coma was triggered by `MiniDumpWriteDump` and persists for the dump-session lifetime regardless of handle closure."*

---

## 3. Audit of the netsec.rs fix itself (the +49/-42 diff)

The fix touches exactly two functions. Both are **correct as far as they go**, with honest inline documentation. Detailed review:

### `block_outbound_for_pid` fix (`:311-336`)
- The `Result<Self, KitError>` return type is the right call — it forces the caller to handle the failure. The `?` at the call site (`:263`) propagates correctly.
- The error message is specific and actionable (names `FWPM_CONDITION_ALE_APP_ID`, explains why PID isn't a valid condition).
- The `let _ = pid` keeps the signature stable for a future AppId implementation without an unused-variable warning.
- The now-dead struct fields (`protocol`, `port` in `WfpBlockRule` at `:60-61`) remain — they were already dead in the old code and aren't made worse by the fix, but they're misleading (an operator setting `protocol=6, port=443` expects it to matter). Consider removing or marking them.
- **No regression introduced.** The `WfpSilenceGuard` RAII atomicity is intact: a mid-loop `?` drops the partially-built guard, closing the session and removing any filters added before the failure.

### `choke_edr_qos` fix (`:810-826, 880-898`)
- The `QOS_VERSION` struct (`:818-822`) is correct: `{major=1, minor=0}` is the sole documented version for QoS2. `#[repr(C)]` ensures the 8-byte layout matches Win32.
- The 2-param call (`:884`) matches the corrected signature.
- The `QOSCloseHandle` at `:935` is correct cleanup (closes the handle; the throttle persists in pacer.sys per the comment).
- **Residual issues not addressed by the fix** (carried into §1 NEW-K2): `pid` ignored, host-wide throttle, misleading section-header doc, `add_filter`/`set_flow` return values discarded. The fix team correctly prioritized the UB (arity) but left the semantic bug (no PID scoping).

### Tests (`:946-1200+`)
- The WFP tests (`wfp_rules_*`, `wfp_silence_rejects_empty_pids_without_guard`) test rule **generation** and the empty-PID rejection — they do **not** exercise the new `Err` path of `block_outbound_for_pid`. There is no test asserting that `silence_edr([1234])` now returns an error (it would, on Windows, via the propagated `?`). On the non-Windows floor (`:280-282`) the test `wfp_silence_rejects_empty_pids_without_guard` checks the empty-list rejection but not the per-PID refusal. A test like `assert!(silence_edr(&[1234]).is_err())` would lock in the fail-closed contract and catch any future regression that re-enables the nuke filter. **Recommend adding it.**

---

## 4. 已验证干净的区域 (verified-clean, with evidence)

- **`netsec.rs` WFP RAII lifecycle (`WfpSilenceGuard`, `:114-188`)** — the session-scoping design remains sound after the fix: filters live only as long as the guard, `Drop` closes the BFE session (`:132-149`), `close()` is idempotent (`:184`), atomic install preserved. The K1 fix integrates cleanly with this (the `?` at `:263` drops the partial guard on failure).

- **`netsec.rs` QOS FFI post-fix (`:818-826`)** — the corrected `QOS_VERSION {major:u32, minor:u32}` + 2-param `QOSCreateHandleFn` now matches the documented Win32 signature exactly. The call site (`:883-884`) passes a stack `QOS_VERSION {1,0}`. No more stack/register corruption.

- **`win/va_rw.rs` (`:51-92`)** — both `kread`/`kwrite` correctly chunk at 4KB page boundaries and re-translate per page (`:64,85`), avoiding the cross-page physical-contiguity bug. The K1/K2 fix didn't touch this and it remains sound. `PhysReadError→KrwError` mapping is exhaustive (`:41-49`). (MED-10's MMIO gap is in `pagewalk.rs`, not here — this layer correctly re-translates per page.)

- **`win/ksld.rs` chunking (`:395-474`)** — KslD `kread`/`kwrite` chunk at 0x1000 (`:405,445`) with partial-error reporting (`:427,467`). Device enumeration is off by default (`:342-345`). `Drop` closes the handle (`:387-393`).

- **`win/resolve.rs` (`:44-103`)** — sound NUL-termination, `GetModuleHandleA`→`LoadLibraryA` fallback, null-check on `GetProcAddress`. The QOS fix resolves qwave.dll symbols through this path.

- **`offsets::for_build` (`:299-310`)** — still correctly refuses to floor-match (exact → patch-equivalent allow-list → `None`). The ETW module (NEW-K9) should adopt this.

- **`persistence.rs` unlink/strip validation** — `unlink` validates link/flink/blink canonical (`:88,95`); `strip_protection` validates `eprocess_kva` canonical (`:147`) and writes single bytes; `make_immortal` validates canonical EPROCESS (`:204`). Only the comment (NEW-K14) is wrong.

- **`telemetry.rs::repurpose` (`:159-196`)** — the ntoskrnl-range + slot-0 fallback skip logic here is **correct** (range-based when `ntoskrnl_base/size` resolved, slot-0 fallback otherwise). The problem is solely that this logic wasn't ported to `neutralize_array` (NEW-K4).

- **BYOVD driver embedding** — still no `include_bytes!`/embedded `.sys`. Drivers loaded from disk; driver packs carry only IOCTL codes + layout docs + blocklist status. Correct attribution posture.

- **`EventFrequencyKeeper` (`:380-439`)** — the frequency math (`observe_real_event` rolling window, `should_forge` interval clamp `[100ms, 30s]`) is correct in isolation. The only problem is it feeds the broken forge path (NEW-K21).

---

## 5. Summary table

| ID | Sev | 位置 | One-liner | 状态 (vs 07-08) |
|----|-----|------|-----------|----------------|
| **netsec.rs fix** | | | | |
| NEW-K1 | HIGH | netsec.rs:326-335 | WFP silence nukes host outbound | **FIXED (fail-closed)** |
| NEW-K2 | HIGH | netsec.rs:807-938 | QOS wrong arity + ignores PID | **PARTIALLY FIXED** (arity ✓; PID still ignored) |
| NEW-K3 | MED | netsec.rs:614-767 | Full EDR dump never deleted | **STILL PRESENT** |
| NEW-K4 | MED | telemetry.rs:76-110 | neutralize ret-stubs nt! slot-0 | **STILL PRESENT** (fix only in `repurpose`) |
| NEW-K5 | MED | telemetry.rs:270-299 | detach_edr unlinks ALL minifilters | **STILL PRESENT** |
| NEW-K6 | MED | byovd.rs:401-450 | djb2-only export match → BSOD | **STILL PRESENT** |
| NEW-K7 | MED | main.rs:470-596 | Daemon no-auth kernel-R/W surface | **STILL PRESENT** |
| NEW-K8 | MED | main.rs:540-541 | Daemon predictable `lsass_{pid}.dmp` | **STILL PRESENT** |
| NEW-K9 | MED | etwti.rs:124-175 | ETW for_build floor-matches | **STILL PRESENT** |
| NEW-K10 | MED | cfg.rs:204-234 | Export-name truncation false-match | **STILL PRESENT** |
| NEW-K11 | MED | byovd.rs:296-363 | 1 byte/IOCTL (1M IOCTLs/dump) | **STILL PRESENT** (now affects all drivers) |
| NEW-K12 | MED | etwti.rs:230-254 | No canonicality on chain ptrs | **STILL PRESENT** |
| NEW-K13 | MED | pattern_scan.rs:216 + mod.rs:364-365 | Thread array = Process array | **STILL PRESENT** |
| NEW-K14 | LOW | persistence.rs:183-191 | make_immortal comment says 0x4B | **STILL PRESENT** |
| NEW-K15 | LOW | etwti.rs:261-263 | blind writes u64 to 4-byte field | **STILL PRESENT** |
| NEW-K16 | LOW | driver_load.rs:162-167 | Drop doesn't unload → IOC | **STILL PRESENT** |
| NEW-K17 | LOW | cfg.rs:101-114 | Non-atomic CFG bitmap RMW | **STILL PRESENT** |
| NEW-K18 | LOW | main.rs:347-380 | cfg-bypass mixes UM deref + KM prim | **STILL PRESENT** |
| NEW-K19 | LOW | offsets.rs:864-871 | First qword==4 = PID offset | **STILL PRESENT** |
| NEW-K20 | LOW | offsets.rs:861 | Dead `_scan_limit` | **STILL PRESENT** |
| MED-10 | MED | pagewalk.rs:107-111 | No RAM/MMIO validation on PA | **STILL PRESENT** |
| LOW-10 | LOW | netsec.rs:670-716 | Predictable `nyx_freeze_*.dmp` | **STILL PRESENT** |
| **NEW this pass** | | | | |
| **NEW-K21** | **HIGH** | etw_deception.rs:156-239 | Malformed EVENT_HEADER (wrong size/fields); test entrenches bug | **NEW** |
| **NEW-K22** | **MED** | byovd.rs:296-363 + byovd_drivers/ | VulnDriverIoctl too thin; iqvw64e/WDTKernel/Shield broken via generic loop | **NEW** |
| **NEW-K23** | **LOW** | netsec.rs:592-593 vs 754-755 | freeze_edr_coma doc/code contradict on handle closure | **NEW** |

---

## 6. Priority remediation order

1. **NEW-K21 (HIGH)** — `etw_deception.rs` forged events are structurally invalid; the whole Phase-4 deception subsystem is inert and the test validates the wrong layout. Either fix the `EVENT_HEADER` layout or remove the module until it's correct (it gives a false impression of a working capability).
2. **NEW-K4 (MED, high blast radius)** — `neutralize()` will bugcheck via slot-0 dispatcher. The fix already exists in `repurpose` (`:159-196`) — port it. This is a one-screen edit that prevents a near-certain BSOD on first use.
3. **NEW-K22 (MED, silent corruption)** — operators selecting WDTKernel (the advertised HVCI-safe default) get a silently-broken primitive. Add per-driver `KernelRw` impls or a `works_with_generic_loop()` gate.
4. **NEW-K6 (MED, trivial fix)** — one byte-comparison line in `byovd.rs:444` eliminates a BSOD risk from hash collision.
5. **NEW-K7/K8 (MED, local privesc)** — daemon auth + dump-path hardening.
6. **NEW-K2 residual (HIGH→MED)** — `choke_edr_qos` still throttles host-wide; at minimum propagate the caveat to the docs and consider `UnsupportedPosture` until per-process binding exists.
7. **NEW-K11 + NEW-K22 combined** — the byte/IOCTL loop is both slow/IOCTl-noisy *and* structurally wrong for non-RTCore64 drivers; reworking `ByovdDriver` into per-driver impls addresses both at once.

The K1 fix is solid and is the single most impactful improvement since 07-08 (it converts a self-DoS into a clean failure). The remaining kernel-tier surface has not materially improved.
