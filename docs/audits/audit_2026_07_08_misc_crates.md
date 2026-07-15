# Nyx Misc-Crates Audit — 2026-07-08 (fresh line-by-line)

Scope: `coff`(+tests), `bof-runner`, `profile`, `scripting`, `scripting-rhai`,
`store`, `config`, `config-macros`, `agent-dev`, `parse`, `offset-resolver`,
`minidump-assembler`, `evasion`, `pe` (dead-crate verdict).

Severity rubric + authorization per `_CONTEXT.md`. All line numbers are from
code observed directly in this pass. Prior baseline findings (CRIT-1..LOW-12)
live in `server`/`protocol`/`trex`/`implant-*` — **none are in these crates**,
so there is nothing to re-verify here; every finding below is NEW.

---

## CRITICAL

### [CRITICAL] Compile-time config "encryption" ships the key next to the ciphertext — extractor claim is false
- **位置:** `crates/config/src/lib.rs:6-9` (doc claim); `crates/config-macros/src/lib.rs:45-51` (emitted tokens)
- **已核验:** The proc-macro expands `embed!("path")` into:
  ```rust
  nyx_config::decrypt(
      &[#(#key_bytes),*],          // <- 32-byte ChaCha20 key as a literal
      &[#(#nonce_bytes),*],        // <- 12-byte nonce as a literal
      &[#(#ct_bytes),*][#pad..],   // <- ciphertext (+ leading decoy pad)
  )
  ```
  `encrypt()` (`config/src/lib.rs:40-57`) generates a fresh OsRng key+nonce per
  build and the macro bakes **all three** (key, nonce, ct) into `.rodata` as
  decimal byte arrays. The module doc (`config/src/lib.rs:6-9`) claims this
  produces "static config bytes … differ per build, **defeating
  extractors/signature tools (the CS `1768.py` problem and the BRC4 signing
  problem)**." `1768.py` is a *config extractor*.
- **描述:** This is the classic "encrypted config in binary" trap. Per-build
  randomization does defeat **static signatures** and **build-to-build diffing**
  (real value, and an improvement over CS whose key is derivable). But it does
  **not** defeat *extraction*: the ChaCha20-Poly1305 key, nonce, and ciphertext
  are three adjacent `&[u8]` literals in the same binary. A reverser locates the
  `nyx_config::decrypt` call site (trivial via xref), reads the three arrays,
  and recovers the plaintext config in minutes. The doc explicitly claims
  extractors are defeated; they are not.
- **影响:** False security guarantee operators rely on. An operator who reads
  "defeating extractors" and embeds sensitive C2 host/pipe/AES-key material in
  the baked config, believing it is protected at rest in the binary, has that
  config extracted by any competent analyst who obtains the implant binary —
  burning C2 infrastructure and attribution.
- **修复:** (1) Fix the doc to state the honest boundary: *"defeats static
  byte-signatures and build-diffing; does NOT defeat config extraction — the key
  is embedded in the binary and a reverser can recover the plaintext."* (2) If
  real confidentiality-at-rest is required, derive the key from a value the
  binary does *not* contain (e.g., a value fetched from the C2 at first beacon
  and kept only in memory) — but accept that an offline static binary can always
  be analyzed. (3) Treat the embedded config as "obfuscated, not encrypted" in
  all operator-facing docs and threat models.

---

## HIGH

### [HIGH] `BeaconPrintf` shim: signed-int overflow on attacker-controlled format string → heap OOB write
- **位置:** `crates/bof-runner/src/beacon_api.c:28-31`
- **已核验:**
  ```c
  if (nyx_len < NYX_OUT_CAP - 1) {
      int n = vsnprintf(nyx_out + nyx_len, NYX_OUT_CAP - nyx_len, fmt, ap);
      if (n > 0) nyx_len += n;
  }
  ```
  `vsnprintf` returns the number of chars that *would* have been written (not
  the number actually written). `n` and `nyx_len` are both `int`. `fmt` comes
  from the BOF (`BeaconPrintf(type, fmt, ...)`).
- **描述:** A BOF calling `BeaconPrintf(0, "%1000000000d", 1)` makes `vsnprintf`
  return ~1e9. `nyx_len += n` is **signed-integer overflow → undefined
  behavior** in C (in practice wraps to a negative value). On the *next* call,
  `nyx_len < NYX_OUT_CAP - 1` is true (negative < 16383), and
  `vsnprintf(nyx_out + nyx_len, NYX_OUT_CAP - nyx_len, …)` computes
  `nyx_out + (negative)` (pointer before the buffer) and a huge `size_t`.
- **影响:** Heap out-of-bounds write from a BOF the operator loads. The audit
  context names the BOF loader as attack surface: a trojaned/hostile BOF
  delivered via tasking corrupts the host process heap (the dev agent or, if
  this shim is ever reused, the implant). Reliability crash at minimum;
  potentially exploitable for code exec depending on the heap layout.
- **修复:** Clamp `n` to the bytes actually written:
  ```c
  int room = NYX_OUT_CAP - nyx_len;
  int n = vsnprintf(nyx_out + nyx_len, room, fmt, ap);
  if (n > 0) nyx_len += (n < room - 1) ? n : (room - 1);   /* never advance past cap */
  if (nyx_len >= NYX_OUT_CAP) nyx_len = NYX_OUT_CAP - 1;   /* hard clamp */
  ```
  Also make `nyx_len` `size_t` and bound it explicitly; never let it exceed
  `NYX_OUT_CAP - 1`.

---

## MEDIUM

### [MEDIUM] Credential store chmods only the main DB file — `-wal` / `-shm` sidecars keep cleartext, world-readable
- **位置:** `crates/store/src/store.rs:48-56` (open), `:69-71` (WAL pragma), `:182-188` (`set_private`)
- **已核验:**
  ```rust
  Self::init(&conn)?;                 // line 50 — sets journal_mode=WAL FIRST
  let _ = set_private(path);          // line 51 — chmods ONLY `path` (main db file)
  ...
  conn.pragma_update(None, "journal_mode", "WAL")?;   // line 70
  ...
  fn set_private(path: &Path) ... {
      perms.set_mode(0o600);           // line 186 — only `path`
      std::fs::set_permissions(path, perms)
  }
  ```
  WAL mode makes SQLite create `<db>-wal` and `<db>-shm` sidecar files. They are
  created at `init()` time (before the chmod) and inherit the process umask
  (typically 0644 on a default Linux/macOS install). `set_private` never touches
  them. The `-wal` file holds recently-written credential pages (cleartext,
  `secret TEXT NOT NULL`).
- **影响:** On a shared/multi-user team-server host, any local user can
  `strings <db>-wal` and read harvested credentials (passwords, hashes, tickets,
  keys) without touching the 0600 main file. The 0600 hardening is documented as
  critical (`store.rs:46-47`: "the team-server disk is a single high-value
  target") yet silently misses the very files that carry the live data.
- **修复:** After `init()`, also `set_private` on `format!("{path}-wal")` and
  `format!("{path}-shm")` if they exist. Better: set a restrictive umask
  (`umask(0o077)`) around `Connection::open`, or use SQLite's
  `file:` URI with `?mode=0600` (rusqlite supports `Connection::open_with_flags`
  + `OpenFlags::default()`; pair with an explicit `chmod` of all three paths).

### [MEDIUM] `c2lint` rejects CRLF in `header`/`parameter`/`uri-append`/`uri` but NOT in `set useragent` → User-Agent header injection
- **位置:** `crates/profile/src/lint.rs:99-110` (useragent check); contrast `:67-74` (uri CRLF) and `:204-230` (`check_no_crlf_in_wire_stmts`)
- **已核验:** `set useragent "Mozilla/5.0\r\nX-Inject: yes";` passes lint — the
  useragent branch only tests for Beacon-default IOC fragments
  (`DEFAULT_UA_FRAGMENTS`, line 106) and never calls `has_crlf()`. The envelope
  layer then exposes this value verbatim:
  ```rust
  useragent: profile.option("useragent").map(|s| s.0.clone()),   // envelope.rs:167
  ```
  and the transport applies `ClientEnvelope::useragent` as the HTTP
  `User-Agent` header. The same raw bytes flow to the wire.
- **影响:** A profile (operator-controlled but frequently copy-pasted from the
  public Malleable-C2-Profiles corpus) carrying a CRLF in `set useragent`
  produces a malformed/injected HTTP request — request splitting against the
  team server's fronting proxy or the implant's outbound HTTP stack. The other
  three wire-carrying statements ARE guarded, which makes this gap inconsistent
  and easy to assume-covered.
- **修复:** In the `Some(u) =>` arm of the useragent match, add
  `if has_crlf(u.as_str()) { d.push(err(0, "useragent contains CR/LF (HTTP header injection risk)")); }`.

### [MEDIUM] Dev-agent screenshot writes to a predictable `/tmp/nyx_shot_<pid>.png` path — symlink race → local file corruption/deletion
- **位置:** `crates/agent-dev/src/lib.rs:307` (`do_screenshot`), `:503` (`do_screenwatch`)
- **已核验:**
  ```rust
  let tmp = format!("/tmp/nyx_shot_{}.png", std::process::id());   // line 307
  ...
  std::process::Command::new(prog).arg("-x").arg(&tmp).output();   // screencapture/scrot writes here
  ...
  let _ = std::fs::remove_file(&tmp);                              // then unlinked
  ```
  PID is enumerable (`ps`). `/tmp` is world-writable and shared.
- **描述:** Classic `/tmp` symlink attack. A local unprivileged user pre-creates
  `/tmp/nyx_shot_<expected_pid>.png` as a symlink to a victim file (e.g.,
  `~/.ssh/authorized_keys`, a project file). When the dev agent screenshots, the
  capture tool follows the symlink, **truncates and overwrites** the target with
  PNG bytes; the agent then `remove_file`s the symlink (which on most Unix
  unlinks the symlink, not the target — but the truncate already happened).
- **影响:** Local file corruption/destruction of an arbitrary file the agent
  user can write. If the dev agent is run as root in a shared dev box or CI
  container, this is a root-writable-file corruption vector for any non-root
  user who can place a symlink in `/tmp`.
- **修复:** Use `tempfile::NamedTempFile` (already a dep via `tempfile` in
  tests) or write under the agent's `work_dir` rather than a fixed `/tmp` name.
  At minimum use `O_NOFOLLOW`/`O_EXCL` semantics. Note `do_screenwatch`
  (`:503`) repeats the same pattern with `/tmp/nyx_sw_<pid>_<i>.png`.

---

## LOW

### [LOW] `do_hashdump` (macOS shadow) interpolates a filesystem-derived username into `sh -c "<cmd>"`
- **位置:** `crates/agent-dev/src/lib.rs:569-572`
- **已核验:**
  ```rust
  let user = name_str.trim_end_matches(".plist");
  let shadow = std::process::Command::new("sh")
      .arg("-c")
      .arg(format!("dscl . -read /Users/{user} AuthenticationOptions ...; cat .../{user}.plist ..."))
      .output();
  ```
  `user` comes from the filename of an entry in
  `/var/db/dslocal/nodes/Default/users/`.
- **描述:** If that directory ever contains a file like `a;id;.plist`, `user`
  becomes `a;id;` and the shell command executes `id`. Today the directory is
  OS-controlled and writing to it requires root (so the "attacker" already won),
  but the pattern is fragile: any future refactor that draws the username from a
  less-trusted source turns this into direct shell injection.
- **影响:** None today (root-only write); latent injection pattern.
- **修复:** Don't use `sh -c` with interpolated filenames. Either read the plist
  directly (`std::fs::read` + a plist parser) or pass `user` as an argv element
  to a fixed pipeline, not via a shell string. Same for `run_shell_raw`/`run_shell`.

### [LOW] `do_net` fallback treats any unknown query string as a shell command
- **位置:** `crates/agent-dev/src/lib.rs:415`
- **已核验:**
  ```rust
  other => return Response::Output(run_shell_raw(other).into_bytes()),
  ```
  where `run_shell_raw` runs `sh -c "<other>"`.
- **描述:** By design the operator is trusted and `Net { query }` arrives over
  the encrypted tasking channel, so this is RCE-the-operator-can-already-do.
  But the behavior is surprising: a typo or an unrecognized query keyword (e.g.
  `"ls"`) is silently executed as a shell command rather than rejected, which
  can mask protocol/client bugs and produces inconsistent results across query
  spellings.
- **影响:** Soft — operator-confusion / masked client bugs. Not a privilege
  boundary.
- **修复:** Reject unknown query values with `Response::Err("net: unknown query …")`
  instead of falling back to `sh -c`. If a raw-shell escape is wanted, expose it
  via the explicit `Shell` command (which already exists, `lib.rs:224`).

### [LOW] `apply()` REL32 arithmetic uses non-wrapping `i64` subtraction (debug-build panic on pathological resolver output)
- **位置:** `crates/coff/src/lib.rs:358`
- **已核验:**
  ```rust
  let v = cur.wrapping_add((target as i64 - loc as i64 - 4) as i32);
  ```
  `cur.wrapping_add(…)` is safe, but the inner `target as i64 - loc as i64 - 4`
  uses plain `-`, which **panics on overflow in debug builds** (release wraps).
- **描述:** For real Windows user-space addresses (`target` and `loc` both in
  `[0, 0x7FFF_FFFF_FFFF_FFFF)`), the subtraction cannot overflow i64, so this is
  unreachable in practice. A `SymbolResolver` that deliberately returns
  `u64::MAX` could trip a debug panic. The codebase runs `panic = "abort"`, so a
  debug panic kills the process.
- **影响:** None on the production path; theoretical debug-only crash.
- **修复:** Make the wrapping explicit: `(target.wrapping_sub(loc).wrapping_sub(4)) as i32`.

### [LOW] `minidump-assembler` carries a stale doc comment claiming an audited `unsafe` block that no longer exists
- **位置:** `crates/minidump-assembler/src/lib.rs:37-38`
- **已核验:**
  ```rust
  // One unsafe block in `push_struct` for a POD `repr(C, packed)` byte copy —
  // the canonical memcpy-style transmute. Audited; no other unsafe in the crate.
  #![deny(unsafe_code)]
  ```
  The crate is `#![deny(unsafe_code)]` and serializes field-by-field via safe
  `extend_from_slice` (`push_u16/u32/u64`, lines 270-331). There is no
  `push_struct` and no `unsafe` block.
- **影响:** Documentation rot — a reviewer trusting the comment may believe an
  `unsafe` transmute is present and audited when none is. No functional bug.
- **修复:** Delete the stale comment (the `#![deny(unsafe_code)]` already
  proves the property).

### [LOW] Evasion SSN arithmetic can overflow `u32` on a synthetic ntdll image (debug panic)
- **位置:** `crates/evasion/src/syscalls.rs:73` (`s + k`), `:132` (`bs + (target_rva - br) / stride`)
- **已核验:** `halos_gate` does `return Some(s + k);` with `s: u32` from
  `parse_ssn` and `k` up to `MAX_WALK` (512). `tartarus_gate` does
  `Some(bs + (target_rva - br) / stride)`. Both use plain `+`.
- **描述:** A fixture/live image whose `mov eax,<ssn>` encodes a value near
  `u32::MAX` would overflow on add in debug builds. Real SSNs are small
  (< 0x1000), and `hells_gate` only returns `Some` for clean prologues, so this
  is unreachable against a legitimate `ntdll.exe`. The `SyscallSource` is
  trusted (live PEB walk of the host's own ntdll).
- **影响:** Theoretical debug-only panic; not reachable against real ntdll.
- **修复:** `s.wrapping_add(k)` / `bs.wrapping_add(…)`, or clamp.

### [LOW] `offset-resolver` PDB download has no size cap or hard timeout
- **位置:** `crates/offset-resolver/src/main.rs:504-528`
- **已核验:** `download_pdb` does `reader.read_to_end(&mut buf)` with no bound;
  `ureq::get(&url)…call()` relies on ureq's default timeouts.
- **描述:** The Microsoft symbol server is trusted and HTTPS, so this is not an
  attack surface — but a misconfigured proxy or a hung connection could stall
  CI, and a (theoretical) malicious response could OOM the resolver.
- **影响:** CI robustness only.
- **修复:** Cap `buf` at e.g. 256 MiB (`if buf.len() > 256*1024*1024 { bail!() }`)
  and set an explicit `.timeout(Duration::from_secs(60))`.

---

## INFO — dead-crate verdict: `crates/pe`

**Verdict: confirmed dead. Recommend DELETE (or re-`members`-ify).**

- **Evidence of zero dependents:** `grep -rn "nyx_pe\|nyx-pe" --include="*.toml" --include="*.rs" crates/` excluding `crates/pe/` returns **nothing**. The workspace `Cargo.toml` has `exclude = ["crates/pe"]` with a NOTE ("dead crate (zero dependents, zero code references; its sole public fn `resolve_export` is used only by its own tests)"), and `docs/STATUS.md:64` records the exclusion as a completed cleanup. The implant resolves symbols via `nyx-coff` / `nyx-implant-evasionsdk` instead.
- **Code quality if revived:** `crates/pe/src/lib.rs` is actually well-written — every PE-header-derived offset goes through bounds-checked `u16le/u32le` (return `Option`), `checked_add`/`checked_mul` throughout (`resolve_export:40-82`, `parse_sections:95-112`), a `MAX_EXPORT_NAMES = 1<<20` ceiling against pathological export counts (`:60-63`), and `cstr_at` (`:125-134`) is bounds-guarded. The tests (`tests/pe.rs`) cover a real DLL fixture plus malformed-input cases. It does **not** compile in workspace builds (excluded), so it is silently bit-rotting.
- **Decision:** Keeping it `exclude`d-but-present is the worst option (dead code that drifts, won't catch breakage from dependency upgrades). Either:
  1. **Delete** `crates/pe/` entirely (recommended — `nyx-coff` + evasionsdk cover the use case), or
  2. Re-add to `members` so it is at least type-checked in CI as a reference implementation.

---

## 已验证干净的区域 (checked and sound)

- **`crates/coff` parse hardening (`lib.rs:141-263`)** — The BOF loader's parser
  is the named attack surface and it is *well* defended. Every size/offset
  derived from the untrusted COFF header uses `checked_add`/`checked_mul`
  (`:158-161` section table, `:169-173` symbol table, `:181-183` per-section,
  `:209-211` per-reloc, `:235-237` per-symbol). The raw-bytes window is
  **strict** (`:198-206`): a `(raw_ptr, raw_size)` overrunning EOF returns
  `Truncated` rather than silently slicing to `&[]` (the old bug — the test
  `section_raw_window_overrunning_eof_is_rejected`, `tests/coff.rs:157-167`,
  pins the fix). `nsym=0xFFFFFFFF` is rejected, not wrapped
  (`tests/coff.rs:169-183`). `apply()` (`:311-365`) bounds-checks every reloc
  field write (`off+8`/`off+4 ≤ buf.len()`) and resolves symbols by raw index
  via `Symbol::index` (correctly skipping aux records). Reloc-target field
  updates use `wrapping_add` (relocations are deltas by design). The test suite
  exercises the real `bof.o` fixture end-to-end plus four malformed-input
  cases. Allocation amplification is bounded because the per-reloc bounds check
  propagates `Err` immediately (a section declaring `nreloc=65535` but with too
  little reloc data fails on the first unreadable entry, not after allocating
  65535 entries).

- **`crates/bof-runner/src/win.rs` loader layout math (`:52-135`)** — The single
  RWX region is a *documented* dev-harness tradeoff (`:63-69` explicitly warns
  it is a loud EDR signal and the PIC implant must use module stomping +
  per-section perms instead). Layout arithmetic is sound:
  `total = Σ page(virtual_size.max(raw_size))` cannot overflow on the x64-only
  target; `offset` accumulates within `[0, total)` so `base.add(offset)` stays
  in the allocated region; `copy_nonoverlapping(patched, bases[i], patched.len())`
  is safe because `patched.len() == raw_size ≤ page(raw_size) ≤ slot size`;
  symbol→address mapping (`:96-102`) correctly filters `section_number ≥ 1` and
  bounds-checks `section_number ≤ bases.len()` (the `<= len` with `-1` indexing
  is correct). The `eprintln!` that previously leaked the shim's exec-memory
  address was already removed (`:148-149`).

- **`crates/profile/src/lexer.rs` `scan_string` (`:110-192`)** — `\xNN` escape
  bounds-check is correct: `if *i + 2 >= b.len()` (`:160`) rejects when fewer
  than two hex digits remain (no off-by-one — verified against the one-digit-then
  -EOF case). Unterminated string / trailing backslash produce clean `Err`.
  `hex_val`/`hex_pair` (`:194-205`) are total. Unknown escapes are kept
  literally (lenient, documented).

- **`crates/profile/src/parser.rs` recursion (`:126-225`)** — Block nesting is
  capped at `MAX_DEPTH = 64` (`:29`) with `checked_add` on the depth counter
  (`:178-182`); a hostile profile of nested blocks cannot overflow the 8 MiB
  stack. Statement arg collection (`:201-213`) terminates on `;` or EOF. The
  context-sensitive `header "Cookie";` (1-arg terminator) vs
  `header "N" "V";` (2-arg statement) disambiguation (`:174-200`) is purely
  structural (peek for `{`) and needs no block-name awareness.

- **`crates/profile` HTTP-splitting lint coverage (`lint.rs:67-74, 204-230`)**
  — `uri`, and every `header`/`parameter`/`uri-append` statement arg anywhere in
  the client/server subtree, is scanned for CR/LF and rejected as `Error`
  (`has_crlf`, `:195-198`). This is the right defense *for those fields* (the
  one gap, `set useragent`, is reported above as MEDIUM).

- **`crates/scripting` + `crates/scripting-rhai` sandbox (`scripting-rhai/src/lib.rs:26-57`)**
  — The Rhai engine is resource-capped before any script runs:
  `max_call_levels(64)`, `max_operations(1_000_000)`, `max_string_size(64 KiB)`,
  `max_array_size(4096)`, `max_variables(512)`, `max_functions(64)`,
  `max_expr_depths(32,32)` (`:32-39`). The **only** host function registered is
  `nyx_log` (`:40-42`) — no file, network, process, env, or module-loading
  surface is exposed, so there is no path for an operator script to reach
  `unsafe`/IO. `Engine` is `Send+Sync` (held in `Arc<Engine>`) and `dispatch`
  (`:51-57`) silently ignores a missing/throwing handler — no panic propagation
  to the EventBus. `EventBus` (`bus.rs`) correctly splits `&mut self` register
  from `&self fire`; the built-in `FirstBloodHook` avoids nested-lock deadlock
  by releasing the `seen` lock before taking the `records` lock (`builtins.rs:77-85`).
  Operator scripts are trusted, but the sandbox additionally bounds hostile
  `loop {}` / unbounded-concat OOM.

- **`crates/store` SQL layer (`store.rs:92-160`)** — Every query is fully
  parameterized (`params![…]` with `?N` placeholders): `upsert:103-113`,
  `get:138`, `delete:150`; `list`/`count` take no user input. No string
  concatenation anywhere in SQL. `Mutex<Connection>` serializes writes; lock
  poison surfaces as `StoreError::Poisoned` rather than panicking
  (`:93,119,133,147,157`). Schema is a single `CREATE TABLE IF NOT EXISTS`
  (`:73-85`) with a composite `PRIMARY KEY (realm, user, kind)` matching the
  CS upsert semantic — no migration hazard. `foreign_keys=ON` + `synchronous=NORMAL`
  + WAL is the correct ACID profile for a credential vault. (The chmod scope gap
  is reported separately as MEDIUM.)

- **`crates/config` / `config-macros` crypto core (`config/src/lib.rs:40-74`)**
  — Setting aside the false-extractor-claim (CRITICAL above), the *cryptography*
  is sound: fresh OsRng 32-byte key + 12-byte nonce per `embed!` call site
  (`:44-45, config-macros:73-74`); ChaCha20-Poly1305 AEAD with tag verification
  on decrypt (`:65-73`); no nonce reuse within or across builds. Macro hygiene is
  correct — it emits an absolute path `nyx_config::decrypt(…)` so it does not
  depend on the call site's `use` imports. `resolve()` (`config-macros:57-65`)
  joins relative paths against `CARGO_MANIFEST_DIR`, but this runs at *compile*
  time on the trusted build host, so path traversal is not an attack surface.

- **`crates/agent-dev` beacon loop crypto (`lib.rs:38-128`)** — Fresh
  `ImplantKeypair::generate()` per process start (`:39`), so session keys never
  recur across restarts. The `counter` (`:68`) is monotonic across check-in +
  loop + batch flushes (`:74, 96, 161, 187`) — no nonce reuse within a session.
  Check-in retries re-encrypt the same plaintext under *different* nonces
  (`:72-82`). The frame body is authenticated before any task decoding:
  `open_frame_dir(…, Direction::ServerToClient, &raw)` (`:122`) gates
  `Task::decode_vec` (`:129`); a tag failure is logged and `continue`d, never
  processing unauthenticated bytes. Profile envelope inversion
  (`unwrap_server_envelope:205-216`) falls back to raw bytes on decode failure,
  but the AEAD open is the ultimate integrity gate. `safe_resolve`
  (`:814-863`) rejects absolute paths, `..` components, **and** symlink escape
  via `canonicalize` + `starts_with(canon_work)`, with explicit test coverage
  for the symlink case (`tests:978-996`).

- **`crates/parse` (`lib.rs`, 545 lines)** — `#![forbid(unsafe_code)]` (`:16`).
  Every parser is a best-effort `&str → Vec<Row>` splitter that uses
  `split_whitespace` / `and_then(parse)` / `unwrap_or(default)` — no panicking
  indexing on attacker-shaped shell output. `parse_size` (`:227-229`) and
  `is_size_token` (`:222-225`) handle thousands-separators. The CSV splitter
  (`:305-320`) is a minimal char-by-char state machine with no recursion. All
  parsers silently skip malformed lines (documented intent, `:11-13`).

- **`crates/evasion` SSN algorithms (`syscalls.rs`, `stub.rs`)** —
  `#![no_std]`-portable, pure-algorithm. `parse_ssn` (`:48-54`) bounds-checks
  `bytes.len() >= 8` before reading. `halos_gate`/`tartarus_gate` use
  `checked_mul`/`checked_sub`/`checked_add` for RVA math (`:69-81`) and the
  nearest-neighbour selection in `tartarus_gate` (`:107-121`) structurally
  guarantees the `ar - br` and `as_ - bs` subtractions cannot underflow (the
  `as_ > bs` guard at `:125` prevents div-by-zero). `stub.rs` templates are pure
  Vec builders with hardcoded x86 opcodes. (The theoretical u32 SSN-add
  overflow is noted as LOW.)

- **`crates/minidump-assembler` (`lib.rs:165-331`)** — Write-only (no parsing),
  `#![deny(unsafe_code)]`. All offsets are `u32` constants computed up front
  (`:167-183`); `total_size = base_rva + raw.len()` is a single `Vec` capacity
  with a `debug_assert_eq!(out.len(), total_size)` drift check (`:256`).
  Serialization is field-by-field safe `extend_from_slice` (`push_u16/32/64`,
  `:270-331`). `raw.len() as u64` for the descriptor (`:248`) cannot truncate.
  The only blemish is the stale `unsafe`-block doc comment (LOW above).

- **`crates/offset-resolver` (`main.rs`)** — HTTPS-only, hardcoded MS symbol
  server base; the URL path components (`guid`, `age`) are hex/numeric-filtered
  (`format_symserver_guid:450-454`), so no request-splitting into the URL. PE
  parsing delegates to `goblin` (`:470`), which handles malformed PEs by
  returning `Err`. PDB walking delegates to the `pdb` crate with correct use of
  the `FallibleIterator` + `finder.update` contract (`:259-283`, with an
  explicit comment on why the finder must be built incrementally). All
  section-index arithmetic is bounds-checked (`:598-604`). (Download size cap is
  LOW above.)

---

## Summary table

| Sev | Count | Headline |
|-----|-------|----------|
| CRITICAL | 1 | Config-in-binary ships the key; "defeats extractors" claim is false |
| HIGH | 1 | `BeaconPrintf` int overflow → heap OOB write from a hostile BOF |
| MEDIUM | 3 | Store `-wal`/`-shm` not 0600; lint misses CRLF in `set useragent`; screenshot `/tmp` symlink race |
| LOW | 6 | `do_hashdump`/`do_net` shell patterns; coff REL32 debug arith; minidump stale comment; evasion SSN add; resolver size cap |
| INFO | — | coff/bof-runner/profile/scripting/rhai/store/agent-dev-crypto/parse/evasion/minidump all verified sound; `pe` confirmed dead (recommend delete) |

The COFF loader — the named attack surface — is the **best-hardened** crate in
this set: the author clearly anticipated the malformed-object / wraparound /
silent-truncation classes and pinned them with tests. The highest-impact bug is
**not** in coff itself but in the `beacon_api.c` shim that bof-runner links
against.
