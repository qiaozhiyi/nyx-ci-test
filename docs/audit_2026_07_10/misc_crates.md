# Nyx Misc-Crates Audit — 2026-07-10 (line-by-line re-verification + fresh pass)

Scope: `store`, `scripting`, `scripting-rhai`, `agent-dev`, `evasion`, `parse`,
`minidump-assembler`, `offset-resolver`, `bof-runner`, `rest`.

Authorization + severity rubric per `_CONTEXT.md`. The 07-08 baseline findings
that live in these crates are the three tagged `MED-NEW-MISC1/3` and the
`LOW`/`INFO` items; each is re-verified below with current line numbers.
Uncommitted changes in this domain: **only `crates/agent-dev/src/lib.rs`** (+2/-1,
`git diff --stat` confirmed). Every other misc file is unchanged since the
07-08 read, so findings there are re-verified at their (identical) line numbers.

---

## The one fix in this domain — verified

### `agent-dev/src/lib.rs` — ImplantKeypair::generate now handles CSPRNG failure
- **位置:** `crates/agent-dev/src/lib.rs:38-40` (was `:39`)
- **状态:** NEW FIX (this diff); correct
- **已核验:**
  ```rust
  let kp = ImplantKeypair::generate()
      .map_err(|_| anyhow::anyhow!("CSPRNG failure during implant keypair generation"))?;
  ```
  `ImplantKeypair::generate` (`protocol/src/crypto.rs:298`) returns
  `Result<Self, GenerateError>`. The prior code was `let kp =
  ImplantKeypair::generate();` which would not have compiled under the current
  protocol crate signature, so this diff is the propagation of a *protocol-side*
  hardening (key generation can now surface `GenerateError` instead of
  panicking). The `.map_err(|_| …)` discards the structured error variant, but
  that is acceptable: `GenerateError` carries no detail an operator needs.
- **Audit of the fix itself:** The retry loop that follows (`:73-82`) still does
  `counter += 1` *after* `encode_frame` but *before* the `match` on the POST
  result — so a failed check-in increments the counter and the next attempt
  re-encrypts under a fresh nonce. No nonce reuse introduced. The session key
  `key` is derived once from the freshly-generated ephemeral keypair
  (`:42`), matching the one-key-per-process design. **No new bug from this
  change.**
- **Note (not a finding):** `server_pub` in `main.rs:13-16` is parsed with
  `.expect(...)` (panics on bad `NYX_SERVER_PUB`). That is operator-config at
  process start, before any network — acceptable for a dev agent; `panic=abort`
  just exits with a clear message.

---

## RE-VERIFICATION of prior 07-08 findings

### [MEDIUM] store chmods only the main DB file — `-wal`/`-shm` sidecars keep cleartext, world-readable
- **位置:** `crates/store/src/store.rs:48-56` (open), `:69-71` (WAL pragma), `:181-188` (`set_private`)
- **状态:** **STILL PRESENT** (unchanged since 07-08; not in the fix set)
- **已核验:**
  ```rust
  Self::init(&conn)?;                 // line 50 — journal_mode=WAL runs here
  let _ = set_private(path);          // line 51 — chmods ONLY `path`
  ...
  fn set_private(path: &Path) ... {
      perms.set_mode(0o600);          // line 186 — only `path`
      std::fs::set_permissions(path, perms)
  }
  ```
  `init()` (`:70`) sets `journal_mode=WAL`, which makes SQLite create
  `<db>-wal` and `<db>-shm` sidecars on the first write. `set_private` only
  ever touches `path` (the main db file). The `-wal` file holds recently-written
  credential pages (cleartext `secret TEXT NOT NULL`) and inherits the process
  umask (typically 0644). The module doc (`:46-47`) explicitly calls the disk a
  "single high-value target," so the 0600 intent is documented and load-bearing.
- **影响:** On a shared/multi-user team-server host, any local user can
  `strings <db>-wal` and read harvested credentials without touching the 0600
  main file.
- **修复:** After `init()`, also `set_private` on `format!("{path}-wal")` and
  `format!("{path}-shm")` if they exist (they may appear lazily on first write,
  so re-chmod on each `open` *and* guard the first `upsert`). Better: set a
  restrictive `umask(0o077)` around `Connection::open`, or open via
  `Connection::open_with_flags` and chmod all three paths defensively
  (ignore "not found").

### [MEDIUM] dev-agent screenshot writes to a predictable `/tmp/nyx_shot_<pid>.png` — symlink race
- **位置:** `crates/agent-dev/src/lib.rs:308` (`do_screenshot`), `:504` (`do_screenwatch`)
- **状态:** **STILL PRESENT** (unchanged; not in the fix set)
- **已核验:**
  ```rust
  let tmp = format!("/tmp/nyx_shot_{}.png", std::process::id());   // line 308
  ...
  std::process::Command::new(prog).arg("-x").arg(&tmp).output();   // writes via symlink
  ...
  let _ = std::fs::remove_file(&tmp);                              // then unlinks
  ```
  PID is enumerable; `/tmp` is world-writable. A pre-placed symlink at the
  predicted path makes the capture tool truncate/overwrite the symlink target
  with PNG bytes. `do_screenwatch` (`:504`) repeats the pattern at
  `/tmp/nyx_sw_<pid>_<i>.png`.
- **影响:** Local file corruption/destruction of an arbitrary agent-writable
  file; root-writable-file corruption if the dev agent runs as root in a shared
  dev box/CI container.
- **修复:** Write under the agent's `work_dir` (already a configured, private
  root) or use `tempfile::NamedTempFile` (`tempfile` is already a dep). At
  minimum `O_NOFOLLOW`/`O_EXCL`.

### [LOW] `do_hashdump` (macOS shadow) interpolates a filesystem-derived username into `sh -c`
- **位置:** `crates/agent-dev/src/lib.rs:568-573`
- **状态:** **STILL PRESENT**
- **已核验:** `user = name_str.trim_end_matches(".plist")` then
  `format!("dscl . -read /Users/{user} ...; cat .../{user}.plist ...")` fed to
  `sh -c`. `user` derives from a filename in
  `/var/db/dslocal/nodes/Default/users/` (root-writable today, but the pattern
  is a latent injection sink).

### [LOW] `do_net` fallback runs any unknown query string as a shell command
- **位置:** `crates/agent-dev/src/lib.rs:416`
- **状态:** **STILL PRESENT**
- **已核验:** `other => return Response::Output(run_shell_raw(other).into_bytes())`
  — an unrecognized `Net { query }` keyword is silently `sh -c`'d. Operator-
  trusted input, but masks client/protocol typos as shell execution.

### [LOW] `minidump-assembler` stale doc comment claims an audited `unsafe` block that does not exist
- **位置:** `crates/minidump-assembler/src/lib.rs:37-38`
- **状态:** **STILL PRESENT**
- **已核验:**
  ```rust
  // One unsafe block in `push_struct` for a POD `repr(C, packed)` byte copy —
  // the canonical memcpy-style transmute. Audited; no other unsafe in the crate.
  #![deny(unsafe_code)]
  ```
  There is no `push_struct` and no `unsafe` block (serialization is safe
  `extend_from_slice`, `:288-331`). Doc rot — a reviewer may believe an audited
  transmute exists when none does.

### [LOW] evasion SSN arithmetic uses plain `+` (debug-build overflow on synthetic ntdll)
- **位置:** `crates/evasion/src/syscalls.rs:73` (`s + k`), `:132` (`bs + …`)
- **状态:** **STILL PRESENT**
- **已核验:** `halos_gate` `return Some(s + k);` (`:73`) with `s: u32`; `tartarus_gate`
  `Some(bs + (target_rva - br) / stride)` (`:132`). The surrounding RVA math
  (`:70-71, 76`) correctly uses `checked_mul/checked_sub/checked_add`; only the
  final SSN adds are plain. Real SSNs are tiny, so this is unreachable against
  a legitimate ntdll; `panic = "abort"` makes a debug panic fatal.
- **修复:** `s.wrapping_add(k)` / `bs.wrapping_add(...)`.

### [LOW] `offset-resolver` PDB download has no size cap or hard timeout
- **位置:** `crates/offset-resolver/src/main.rs:504-528` (`download_pdb`)
- **状态:** **STILL PRESENT**
- **已核验:** `reader.read_to_end(&mut buf)` (`:523-525`) with no bound; `ureq::get`
  (`:511-514`) relies on ureq defaults. MS symbol server is trusted/HTTPS, so not
  an attack surface, but a hung proxy stalls CI and a (theoretical) huge response
  OOMs the resolver.
- **修复:** cap `buf` at e.g. 256 MiB; `.timeout(Duration::from_secs(60))`.

---

## NEW findings (not in 07-08 baseline)

### [LOW] `offset-resolver` arg parser panics (index OOB) when an option is the last token with no value
- **位置:** `crates/offset-resolver/src/main.rs:52-89`
- **状态:** NEW
- **已核验:**
  ```rust
  while i < args.len() {
      match args[i].as_str() {
          "--pdb-path" => { i += 1; pdb_path = Some(PathBuf::from(&args[i])); }   // i may == args.len()
          "--guid"     => { i += 1; guid = Some(args[i].clone()); }
          "--age"      => { i += 1; age = Some(args[i].parse()?); }
          "--build"    => { i += 1; build = Some(args[i].parse()?); }
          "--ntoskrnl" => { i += 1; ntoskrnl = Some(PathBuf::from(&args[i])); }
          "--fltmgr"   => { i += 1; fltmgr = Some(PathBuf::from(&args[i])); }
          "--out"      => { i += 1; out = PathBuf::from(&args[i]); }
          ...
      }
      i += 1;
  }
  ```
  `nyx-offset-resolver --pdb-path` (no following value) makes `i` advance to
  `args.len()`, then `args[i]` is an **index-out-of-bounds panic**. `panic =
  "abort"` kills the process. All seven value-taking options share the bug.
- **描述:** Hand-rolled arg parser with no guard that a value follows. The
  `--age`/`--build` arms additionally call `.parse()?` (which would error
  cleanly on a non-numeric), but the indexing panic happens first.
- **影响:** Operator-only (the resolver is a server-side/CI build tool taking
  argv from the operator). Not attacker-reachable. A typo at the CLI crashes
  the build step with a Rust panic backtrace instead of a clean usage message.
  Severity LOW (robustness/UX), not security.
- **修复:** Before each `args[i]` read, check `i < args.len()` and emit a clean
  `anyhow!("--<flag> requires a value")`. Or use `clap`/`pico-args` (the crate
  already pulls `anyhow`; a structopt-style derive would remove this whole
  class).

### [LOW] `do_screenwatch` hardcodes `screencapture` — silently no-ops on Linux
- **位置:** `crates/agent-dev/src/lib.rs:507-510`
- **状态:** NEW
- **已核验:** `do_screenshot` (`:307-324`) correctly selects `prog` per OS
  (`screencapture` on macOS, `scrot` on Linux). `do_screenwatch` (`:507`)
  instead hardcodes `"screencapture"`:
  ```rust
  let r = std::process::Command::new("screencapture")
      .arg("-x").arg(&tmp).output();
  ```
  On Linux `screencapture` does not exist → `Command::output()` returns `Err`
  → the `if let Ok(out) = r` arm is skipped → loop produces no chunks → the
  function returns `Response::Err("screenwatch: screencapture not available")`
  (`:536-538`).
- **描述:** Copy/paste drift between the two screenshot paths. The error
  message ("screencapture not available") is also misleading on Linux (the real
  issue is the wrong binary name). No security impact; a dev-loop correctness
  gap that makes screenwatch appear "unsupported" on Linux when it could work
  via scrot.
- **影响:** Dev-loop only; screenwatch silently broken on Linux dev hosts.
- **修复:** Extract the same `prog` selection `do_screenshot` uses into a helper
  and call it from both. (Also fix the `/tmp` path in the same pass — see the
  MEDIUM symlink-race finding.)

### [LOW] `mask_secret` docstring describes `first2….last2` masking; implementation always returns `"********"`
- **位置:** `crates/store/src/model.rs:69-74`
- **狀態:** NEW
- **已核验:**
  ```rust
  /// Mask a secret for list/preview rendering: `first2….last2` when long enough,
  /// else a bare `…. Sentinel for "this view is masked; call ?reveal=1 for
  /// cleartext". UTF-8-safe (char-based, not byte-slice).
  pub fn mask_secret(_s: &str) -> String {
      "********".to_string()
  }
  ```
  The parameter is `_s` (unused). The test (`:94-98`) pins the `"********"`
  output, so the constant behavior is intentional; the doc is stale.
- **描述:** Doc/impl mismatch. The actual behavior (uniform 8 stars) is
  *more* conservative than the documented partial-reveal, so this is not a
  secret-leak regression — it is doc rot that could mislead an operator into
  believing partial secret bytes are exposed in list views when they are not,
  or conversely mislead a future maintainer who trusts the doc and "restores"
  the partial-reveal behavior (which would then be a real leak).
- **影响:** None functionally; trust/doc hazard.
- **修复:** Rewrite the doc to: *"Always returns a fixed `'********'` sentinel.
  Intentionally reveals no secret bytes; callers gate cleartext behind
  `?reveal=1`."* (Or, if partial reveal was genuinely intended, implement it
  char-based as the doc claims — but uniform masking is the safer choice for a
  credential vault.)

### [LOW] `LogHook::on_event` and `FirstBloodHook` use `.lock().unwrap()` — panic on poison propagates into the EventBus
- **位置:** `crates/scripting/src/builtins.rs:44` (LogHook), `:79,83` (FirstBloodHook)
- **状态:** NEW
- **已核验:**
  ```rust
  self.records.lock().unwrap().push(line);        // LogHook, :44
  let is_first = self.seen.lock().unwrap().insert(...);   // FirstBloodHook, :79
  self.records.lock().unwrap().push(...);                 // FirstBloodHook, :83
  ```
  The `Hook` trait contract (`hook.rs:16-17`) explicitly states *"Implementations
  must not panic"* and `bus.fire` (`bus.rs:23-27`) calls `h.on_event(event)` with
  no catch_unwind:
  ```rust
  pub fn fire(&self, event: &Event) {
      for h in &self.hooks {
          h.on_event(event);
      }
  }
  ```
  `EventBus::fire` is invoked from beacon handlers (concurrent axum context per
  the rhai docstring, `scripting-rhai/src/lib.rs:29`). A poisoned Mutex (because
  *some other* hook panicked while holding a lock) makes `.unwrap()` panic here,
  which — under `panic = abort` — tears down the team server mid-beacon.
- **描述:** The hooks themselves don't visibly panic on the happy path, but
  `RhaiHook::dispatch` (`scripting-rhai/src/lib.rs:51-57`) silently swallows
  Rhai errors (good), so poison shouldn't originate from the rhai path. The
  risk is a *future* hook that panics while holding its own lock: the poison
  then cascades through these `.unwrap()`s on the next event. The trait comment
  asks for non-panicking impls, but the reference built-ins themselves violate
  that guidance by using `unwrap()` on lock acquisition. (The store layer, by
  contrast, correctly maps poison to `StoreError::Poisoned` — `store.rs:93` etc.
  — setting the right pattern these hooks should follow.)
- **影响:** Robustness: a single panicking hook can later down the whole server
  via these unwraps. Not directly attacker-triggerable (events come from
  authenticated implant traffic / operator API).
- **修复:** Either (a) match the store pattern — return early / log on
  `Err(PoisonError)` rather than `unwrap()` — or (b) wrap `fire`'s hook call in
  `std::panic::catch_unwind` (hooks are `Send+Sync` but not `UnwindSafe` by
  default; would need `AssertUnwindSafe`). Option (a) is simpler and matches
  the existing crate convention.

---

## INFO — checked and sound (with evidence)

- **`store` SQL layer (`store.rs:92-160`)** — Every query is fully parameterized
  (`params![...]` with `?N` placeholders): `upsert:103-113`, `get:138`,
  `delete:150`; `list`/`count` take no user input. No string concatenation
  anywhere in SQL — **no SQL injection**. `Mutex<Connection>` serializes writes;
  poison surfaces as `StoreError::Poisoned` rather than panicking
  (`:93,119,133,147,157`). Schema is `CREATE TABLE IF NOT EXISTS` (`:73-85`)
  with composite `PRIMARY KEY (realm, user, kind)` matching the CS upsert
  semantic; no migration hazard. `foreign_keys=ON` + `synchronous=NORMAL` + WAL
  is the correct ACID profile for a credential vault. `row_to_record` (`:166-179`)
  degrades a hand-corrupted `kind` label to `Hash` rather than failing the whole
  list — deliberate resilience, documented. (The chmod-scope gap is the MEDIUM
  above.)

- **`scripting-rhai` sandbox (`scripting-rhai/src/lib.rs:26-57`)** — Rhai 1.19,
  resource-capped before any script runs: `max_call_levels(64)`,
  `max_operations(1_000_000)`, `max_string_size(64 KiB)`, `max_array_size(4096)`,
  `max_variables(512)`, `max_functions(64)`, `max_expr_depths(32,32)` (`:32-39`).
  The **only** host function registered is `nyx_log` (`:40-42`) — no file,
  network, process, env, or `import`/module-loading surface. Rhai has no built-in
  file/network/process IO, so with no such FN registered there is **no script
  path to IO or `unsafe`**. `Engine` is `Send+Sync` (held in `Arc<Engine>`).
  `dispatch` (`:51-57`) silently ignores a missing/throwing handler — no panic
  propagation to the EventBus. The event→Map conversion (`:77-100`) clones only
  the event's own fields into the script; nothing host-privileged leaks into the
  script scope. **No sandbox-escape path found.** (Caveat: `max_operations` is
  operation-count, not wall-time; with only `nyx_log` registered — which is O(1)
  — no single cheap builtin can be abused to stall. If a future maintainer adds
  a host FN that does IO, add a wall-clock guard too.)

- **`evasion` SSN algorithms (`syscalls.rs`, `stub.rs`)** — `#![no_std]`+`alloc`,
  pure algorithm. `parse_ssn` (`:48-54`) bounds-checks `bytes.len() >= 8` before
  reading. RVA neighbor-walk math uses `checked_mul/checked_sub/checked_add`
  (`:70-71, 76`). `tartarus_gate` nearest-neighbour selection (`:96-137`) is
  structurally overflow-safe: the `as_ > bs` guard at `:125` prevents the
  `(as_ - bs)` div-by-zero/underflow; `ar - br` / `ar - target_rva` only
  computed when the ordering guarantees non-negativity. `stub.rs` templates are
  pure `Vec` builders with hardcoded x86 opcodes — no parsing, no unsafe.
  (The two plain-`+` SSN adds are the LOW above.) No type confusion in dispatch:
  `SyscallSource` is a read-only `read(rva,len) -> Vec<u8>` + `exports()` trait;
  the algorithms consume bytes uniformly via `parse_ssn`.

- **`minidump-assembler` (`lib.rs:165-331`)** — Write-only (no parsing),
  `#![deny(unsafe_code)]`. All offsets are `u32` constants computed up front
  (`:167-183`); `total_size = memory64_base_rva + raw.len()` (`:185`) cannot
  overflow on a 64-bit host (base is a 0x90 constant; `raw.len()` is `usize`).
  `raw.len() as u64` for the descriptor (`:248`) cannot truncate for any
  realizable in-memory buffer. Serialization is field-by-field safe
  `extend_from_slice` (`push_u16/32/64`, `:270-331`). The `debug_assert_eq!`
  (`:256`) pins the layout. **The dump format is correct**: the
  `parseable_by_minidump_crate` test (`:435-458`) round-trips through the
  `minidump` crate's own parser and confirms exactly one Memory64List range with
  the right base VA + size; the `Memory64List.DataSize` correctly covers only
  header+descriptor (not raw bytes), matching the spec comment (`:211-216`).
  `data_size: raw.len() as u64` (`:248`) is the descriptor's size, not the
  stream's — correct. No integer-overflow or truncation bug in any size
  calculation. (Only the stale `unsafe` doc comment is a LOW.)

- **`offset-resolver` PDB flow (`main.rs`)** — HTTPS-only, hardcoded MS symbol
  server base (`:40`). The URL path component (`format_symserver_guid`,
  `:450-454`) is built by stripping dashes from a hex GUID + appending
  `{:x}` age — both character-filtered by construction, so **no request-splitting
  into the URL and no path traversal** (a GUID with `/` or `..` is not
  producible from `chars().filter(|c| *c != '-')`). PE parsing delegates to
  `goblin` (`:470`), which returns `Err` on malformed input. PDB walking uses
  the `pdb` crate with the correct incremental `finder.update(&iter)` contract
  (`:274, 279`) — the comment at `:253-258` documents *why* (forward-referenced
  FieldList indices). Section-index arithmetic is bounds-checked
  (`sections.get(sec_idx as usize - 1)` with `ok_or_else`, `:598-604`), and the
  1-based vs 0-based indexing is handled correctly. `detect_build_from_pdb`
  (`:182-212`) honestly returns `None` when it can't extract the build (the
  caller falls back to the known table). No supply-chain integrity check on the
  downloaded PDB, but the MS symbol server is the trusted root for Windows
  offsets and the output is bake-time constants reviewed by the operator —
  acceptable threat model. (Download size cap is the LOW above.)

- **`parse` (`lib.rs`, `#![forbid(unsafe_code)]`)** — Every parser is a
  best-effort `&str → Vec<Row>` splitter using `split_whitespace` /
  `and_then(parse)` / `unwrap_or(default)` — no panicking indexing on
  shell-shaped input. `parse_size`/`is_size_token` (`:222-229`) handle
  thousands-separators. The CSV splitter (`:305-320`) is a char-by-char state
  machine with no recursion (unbounded quote nesting just toggles `in_quotes`).
  `parse_ps_posix` correctly skips 8 fields between PID and COMMAND (`:119-121`,
  pinned by the `ps_posix_pathless_command_not_eaten_by_time_field` regression
  test). All parsers silently skip malformed lines (documented `:11-13`). The
  `CredRow` type here is the parser's neutral shape and is distinct from the
  canonical `store::CredRecord` — no drift hazard because `parse` is an input
  boundary, not a persistence type.

- **`rest` (`lib.rs`, `#![forbid(unsafe_code)]`)** — Pure `Deserialize` view
  types + three helpers. `SessionView` carries all server fields including
  `age_secs`/`ja3`/`ja4` (the drift the crate was created to kill), all
  `#[serde(default)]` for forward-compat. `arch_name` (`:87-94`) matches the
  protocol byte mapping (0=x64, 1=arm64, 2=x86) with a safe `_ => "?"` fallback.
  `authed` (`:99-104`) is a pass-through that attaches a bearer token only when
  present. `session_signature` (`:110-123`) deliberately excludes `age_secs` to
  avoid per-second UI churn. No untrusted-input handling beyond serde (which
  fails closed on bad JSON). Sound.

- **`bof-runner/src/win.rs` loader (`:52-135`)** — The single RWX region is a
  *documented* dev-harness tradeoff (`:63-69`). Layout math is sound:
  `total = Σ page(virtual_size.max(raw_size))` cannot overflow on the x64-only
  target; a hostile BOF setting `virtual_size = u32::MAX` makes `VirtualAlloc`
  fail → handled at `:78-80` (null check). `offset` accumulates within `[0,total)`
  so `base.add(offset)` stays in-region; `copy_nonoverlapping` lengths equal
  `raw.len() ≤ page(raw_size) ≤ slot`. Symbol→address mapping (`:96-102`)
  filters `section_number >= 1` and bounds-checks `(section_number as usize) <=
  bases.len()` then indexes `bases[sn-1]` — correct for the `i16` section number
  (`coff/lib.rs:119`). `execute` (`:161-175`) `transmute`s the entry to a fn
  pointer and calls it — this is the inherently-unsafe BOF-execution primitive
  by design; the `nyx_bof_output()` result is read via `CStr::from_ptr` which
  stops at the NUL the shim always writes (`beacon_api.c:11,16`). (The
  `BeaconPrintf` int-overflow → heap-OOB in `beacon_api.c` is the HIGH from
  07-08, unchanged.)

- **`scripting` bus/hook/event (`bus.rs`, `hook.rs`, `event.rs`)** —
  `EventBus` correctly splits `&mut self` register from `&self fire` (`bus.rs`),
  so concurrent axum handlers can fire safely. `FirstBloodHook` avoids nested-
  lock deadlock by releasing the `seen` lock before taking the `records` lock
  (comment at `builtins.rs:77-78`). Event types are plain data. The only
  blemish is the `.lock().unwrap()` panic-on-poison pattern (LOW above).

---

## Summary table

| Sev | Count | Headline |
|-----|-------|----------|
| CRITICAL | 0 | — |
| HIGH | 0 | (07-08's `BeaconPrintf` heap-OOB in `beacon_api.c` is still present but unchanged — tracked under the 07-08 HIGH, not re-filed here) |
| MEDIUM | 2 | store `-wal`/`-shm` not 0600 (STILL PRESENT); screenshot `/tmp` symlink race (STILL PRESENT) |
| LOW | 7 | hashdump/do_net shell patterns (STILL); minidump stale comment (STILL); evasion SSN add (STILL); resolver size cap (STILL); **resolver arg-parser OOB panic (NEW)**; **screenwatch hardcoded `screencapture` (NEW)**; **`mask_secret` doc rot (NEW)**; **scripting hooks `.lock().unwrap()` poison-panic (NEW)** |
| INFO | — | store-SQL, rhai-sandbox, evasion-algo, minidump-format, offset-resolver-PDB, parse, rest, bof-runner-loader, scripting-bus all verified sound |

The single in-domain fix (agent-dev keypair `Result` propagation) is correct and
introduces no new bug. The two MEDIUMs from 07-08 (store WAL perms, screenshot
symlink race) remain unaddressed in this fix pass — they are the highest-priority
open items in this domain. The highest-value *new* finding is the scripting-hook
poison-panic class (LOW today, but it contradicts the crate's own "hooks must not
panic" contract and sets a bad pattern for future hooks).
