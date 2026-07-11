# Nyx Audit — config / config-macros / coff / profile / pe — 2026-07-10

Scope: `config-macros`, `config`, `coff` (+tests), `profile` (lib/ast/lexer/parser/
lint/transform/envelope/c2lint bin), `pe`. Authorization, severity rubric, and
"audit the fixes themselves" directive per `_CONTEXT.md`.

**Headline:** Only two files in this domain changed in the fix-in-progress diff —
`crates/config-macros/src/lib.rs` (+136) and `crates/config/src/lib.rs` (+9).
`coff`, `profile`, and `pe` have **zero** uncommitted changes, so MED-NEW-MISC2
(useragent CRLF lint gap) is untouched and is re-confirmed below, and the 07-08
"cleanest crate" verdict on COFF is re-verified with fresh eyes (it holds, with
three new LOW notes). The CRIT-NEW-3 fix was reworked substantially but is
**incomplete in a way the 07-08 report and fix plan did not anticipate**: the
`NYX_CONFIG_KEY` knob the fix adds is wired only into the `embed!` proc-macro,
which **no production code calls** — the real implant bakes its config via an
inlined path in `implant-win/build.rs` that ignores the knob entirely.

---

## CRITICAL

### [CRITICAL] CRIT-NEW-3 PARTIALLY FIXED — the fix's `NYX_CONFIG_KEY` knob is dead code; the real implant still bakes key+nonce+ct together
- **位置:** `crates/config-macros/src/lib.rs:57-73` (new `resolve_key`), `crates/config-macros/src/lib.rs:42-110` (macro body); `crates/implant-win/build.rs:122-167` (the path that actually ships)
- **状态:** PARTIALLY FIXED (doc honesty = done and good; key-externalization = NOT done for the real implant)
- **已核验:**
  - What the fix did (good): rewrote both module docs to the honest "obfuscation, not confidentiality" boundary (`config-macros/src/lib.rs:8-13`, `config/src/lib.rs:10-14`), removed the false "defeats extractors / 1768.py" claim, added a `NYX_CONFIG_KEY=<64 hex>` env override (`resolve_key` at `:151-163`, `parse_hex_key` at `:166-180`), and — cleverly — surfaces a real `#[deprecated]` compiler warning at every `embed!` call site when the env var is unset (`:84-99`, `const _: () = NYX_CONFIG_DEFAULT_KEY_WARNING;`). I built `cargo build -p nyx-config --tests` and confirmed the warning fires verbatim at each call site. The deprecated-item trick is legitimate and is a genuinely useful operator-facing signal.
  - What the fix did NOT do: the key is **still emitted as a literal array in the same binary as the ciphertext** in both the macro and the real implant. `embed!` still emits `&[#(#key_bytes),*]` (`:104`) next to the ct slice (`:106`). The fix-plan's 方案 A ("密钥不入二进制…运行时从环境变量…读取密钥", `docs/FIX_PLAN_2026-07-08.md:73`) was NOT implemented; what shipped is 方案 B (honest docs) plus a cosmetic env knob.
  - The decisive gap: **the `embed!` proc-macro is never invoked by production code.** A workspace-wide grep for non-comment `embed!` / `nyx_config_macros::embed!` finds exactly three call sites, all in `crates/config/tests/embed.rs:7,16,17` (integration tests). The actual implant config is baked by an **inlined** copy of the scheme in `implant-win/build.rs:122` — `let (key, nonce, ct) = nyx_config::encrypt(&blob);` — which writes `CONFIG_KEY` / `CONFIG_NONCE` / `CONFIG_CT` as three separate `pub static` byte arrays into `OUT_DIR/config_blob.rs` (`build.rs:123-167`), then `implant-win/src/config.rs:52` decrypts with `nyx_config::decrypt(&baked::CONFIG_KEY, &baked::CONFIG_NONCE, baked::CONFIG_CT)`. `nyx_config::encrypt` (`config/src/lib.rs:45-62`) always draws a fresh OsRng key and **never reads `NYX_CONFIG_KEY`**.
  - Net effect: an operator who sets `NYX_CONFIG_KEY=<their-key>` expecting per-operator key separation (the new doc at `config-macros:39-41` explicitly markets this: *"to give each operator/build a unique key"*) gets **no change whatsoever** in the shipped implant binary, because the implant never goes through `embed!`. The knob is effectively dead code for the only consumer that matters.
- **描述:** The 07-08 CRITICAL was "key embedded next to ciphertext, extractor claim false." The doc claim is fixed. But the *structural* problem — three adjacent literal arrays recoverable by any reverser in minutes — is unchanged in the real implant, and the headline new feature (`NYX_CONFIG_KEY`) gives operators a false sense of control because it only affects a macro the implant doesn't use. This is the "fixed the symptom, not the root cause, and added a footgun" pattern the context memo warns about.
- **影响:** (1) Implant config (C2 host, port, URI, server pubkey) remains trivially extractable from any captured implant binary — same as 07-08. (2) An operator relying on the new `NYX_CONFIG_KEY` doc to achieve per-build/per-operator key diversity is silently unprotected — a false-security guarantee, which is exactly the class of bug the original CRIT-NEW-3 was filed against.
- **修复:** Either (a) route the real implant through `NYX_CONFIG_KEY`: have `implant-win/build.rs::bake_config` consult `resolve_key`-equivalent logic (read `NYX_CONFIG_KEY`, fall back to OsRng) so the knob actually controls the shipped key; or (b) if externalization is the goal (方案 A), make `build.rs` emit only the ciphertext and have `config.rs::load()` read the key from `NYX_CONFIG_KEY`/a 0600 sidecar file at runtime (the implant is `#![no_std]`+Windows, so use `GetEnvironmentVariable`/file read, not `std::env`). Either way, **make the doc match the implant path**, and add a test that asserts the implant's baked key equals `NYX_CONFIG_KEY` when set (currently no such test exists). At minimum, if the knob is intentionally macro-only, state that in the doc so operators aren't misled.

---

## HIGH

(none new in this domain this pass. The CRIT-NEW-3 carry-over above is the highest-impact item; the 07-08 HIGH `BeaconPrintf` overflow is in `bof-runner`, out of this domain.)

---

## MEDIUM

### [MEDIUM] MED-NEW-MISC2 STILL PRESENT — `set useragent` still not CRLF-checked; header-injection gap unchanged
- **位置:** `crates/profile/src/lint.rs:99-110` (useragent branch, still no `has_crlf`); contrast `:67-74` (uri) and `:204-230` (`check_no_crlf_in_wire_stmts`, which covers `header`/`parameter`/`uri-append` but not the top-level `set useragent`)
- **状态:** STILL PRESENT (zero diff to `profile/src/lint.rs` in this fix pass — `git diff crates/profile/` is empty)
- **已核验:** The `Some(u) =>` arm (`:104-109`) tests only `DEFAULT_UA_FRAGMENTS` (`:106`) and never calls `has_crlf`. `WIRE_STMTS` at `:207` is `["header", "parameter", "uri-append"]` — `set useragent` is a top-level option, not a statement under `client`/`server`, so the recursive walker at `:208-228` cannot reach it. The value still flows to the wire verbatim: `envelope.rs:167` — `useragent: profile.option("useragent").map(|s| s.0.clone())` — and the transport applies `ClientEnvelope::useragent` as the HTTP `User-Agent` header.
- **描述:** A profile carrying `set useragent "Mozilla/5.0\r\nX-Inject: yes";` passes `c2lint` cleanly and produces request/header splitting when the transport emits it. The other three wire-carrying fields are guarded, making this the one inconsistency an operator would reasonably assume is covered.
- **影响:** Request splitting against the team-server fronting proxy or the implant's outbound HTTP stack from a profile copy-pasted from the public Malleable-C2-Profiles corpus.
- **修复:** In the `Some(u) =>` arm, add `if has_crlf(u.as_str()) { d.push(err(0, "useragent contains CR/LF (HTTP header injection risk)")); }`. One line; the helper already exists at `:195`.

---

## LOW

### [LOW] NEW — `terminator_of` doc says "last" but returns first match (and silently drops argless terminators)
- **位置:** `crates/profile/src/envelope.rs:193-216`
- **状态:** NEW (not in 07-08 baseline)
- **已核验:** Doc comment at `:193` — *"The terminator of a data block = the **last** non-transform statement that declares where bytes goes"* — but the function `return`s on the **first** matching keyword it encounters (`:200`, `:205`, `:209`, `:210` are all early returns inside a forward `for item in &block.items` loop). Additionally the `header`/`parameter` arms use `args.first()?` (`:201`, `:206`); a malformed `header;` with zero args makes `terminator_of` return `None`, silently swallowing the terminator instead of treating it as the (degenerate) terminator it lexically is.
- **描述:** For a well-formed CS profile the terminator is conventionally last and singular, and `check_data_blocks` (`lint.rs:172-188`) already warns on `terms > 1`, so real profiles are unaffected. But the documented invariant is wrong, and a profile with two terminator-class statements (e.g. `header "A"; ... print;`) would (a) earn only a lint *warning*, then (b) have its terminator resolved as the first (`header`) rather than the last (`print`) — diverging from CS semantics and from the contract this module claims.
- **影响:** Latent correctness drift; no live crash. If the envelope layer is later trusted to drive the transport without re-reading the lint result, a dual-terminator profile would shape traffic differently than intended.
- **修复:** Either iterate to the last match (`let mut term = None; for ... { match ... { term = Some(...) } } term`) to match the doc, or fix the doc to say "first" and explicitly document the lint as the guard against the ambiguity. Also handle the argless case explicitly (treat as `Terminator::Header(String::new())` or surface an error) rather than `?`-swallowing it.

### [LOW] 07-08 coff REL32 debug-arith — STILL PRESENT (confirmed, unchanged)
- **位置:** `crates/coff/src/lib.rs:358`
- **状态:** STILL PRESENT (no diff to coff)
- **已核验:** `let v = cur.wrapping_add((target as i64 - loc as i64 - 4) as i32);` — the inner `target as i64 - loc as i64 - 4` uses plain `-`, which panics on overflow in debug builds. Unreachable against real Windows user-space addresses; `panic="abort"` would kill a debug process. (Release wraps.)
- **修复:** `(target.wrapping_sub(loc).wrapping_sub(4)) as i32` — already recommended in 07-08; trivial, still outstanding.

### [LOW] NEW — COFF `ADDR32NB` (0x0002) documented as handled but rejected by `apply()`
- **位置:** `crates/coff/src/lib.rs:14` (doc) vs `:334-362` (apply match)
- **状态:** NEW
- **已核验:** The crate-level doc (`:14`) lists `ADDR32NB (0x02)` among "AMD64 relocation types handled". But `apply()`'s match arms cover only `ADDR64` (`:335`), `REL32` (`:347`), and `REL32_1..=0x0008` (`:347`); `ADDR32NB` falls through to `other => return Err(ApplyError::UnsupportedReloc(other))` (`:361`). The constant `reloc::ADDR32NB` is defined (`:36`) but never matched.
- **描述:** Doc/behavior mismatch. A BOF that emits an ADDR32NB relocation (rare for `.text` call sequences, but legal for RVA-relative data references) would be rejected at load time with a confusing "unsupported relocation 0x0002" error despite the doc claiming support.
- **影响:** None for the common BOF `.text`-only case (REL32-family). A BOF using RVA-relative addressing fails to load.
- **修复:** Either implement ADDR32NB (`buf[off..off+4] = (target as u32).wrapping_add(cur as u32)` — it's an absolute RVA, 32-bit, base-relative) or correct the doc to list only the actually-handled types.

### [LOW] NEW — COFF no `IMAGE_SCN_LNK_NRELOC_OVFL` handling; `nreloc` capped implicitly at u16 but overflow sections misparsed
- **位置:** `crates/coff/src/lib.rs:191` (`let nreloc = u16le(data, so + 32) as usize;`)
- **状态:** NEW
- **已核验:** `nreloc` is read as a raw u16 with no check for the COFF overflow protocol: when a section has > 65535 relocations, the section sets `IMAGE_SCN_LNK_NRELOC_OVFL` (0x01000000) in `characteristics`, `nreloc` is set to the sentinel `0xFFFF`, and the *real* count lives in `VirtualAddress` (= `offset` field) of the first relocation entry. The current parser reads `0xFFFF` literally and tries to consume 65535 10-byte reloc entries from `reloc_ptr`. A legitimately huge section is thus misparsed; a crafted section could also set `nreloc=0xFFFF` with far fewer real entries (the per-entry `data.get(ro..ro+10)` guard at `:212` catches truncation, so no OOB — but parse semantics are wrong).
- **影响:** None for real BOFs (a `.o` from clang/MSVC has < 65535 relocs per section). A pathological/crafted `.obj` is rejected cleanly (Truncated) rather than misinterpreted, because the bounds check fires first — so this is a correctness/spec-completeness note, not a memory-safety gap.
- **修复:** When `characteristics & 0x01000000 != 0`, read the real count from the first reloc's `offset` u32 (and account for the "transitional" first reloc). Low priority given BOF scale.

### [LOW] NEW — COFF `reloc_ptr` not range-checked against header/symbol region (parser accepts relocs aliasing header bytes)
- **位置:** `crates/coff/src/lib.rs:189-220`
- **状态:** NEW
- **已核验:** `reloc_ptr` is read from the section header (`:190`) and used directly as a file offset into `data` (`:209`). There is no check that `[reloc_ptr, reloc_ptr + nreloc*10)` doesn't overlap the COFF header, section table, or symbol/string table. A crafted `.obj` could point `reloc_ptr` at the 20-byte COFF header and have `apply()` relocate against header-derived bytes.
- **描述:** Not a memory-safety bug — every access is bounds-checked via `data.get(...)` / `raw_end <= data.len()`, so no OOB panic. It is a permissiveness issue: the parser will happily decode header/symbol bytes as relocation entries and hand the resulting (garbage) `Reloc` structs to `apply()`, which then writes garbage into section bytes in memory. Since BOFs are operator-loaded but the audit context names "a trojaned/hostile BOF delivered via tasking" as the threat model, a hostile `.obj` that confuses the loader into producing wrong-but-non-crashing section bytes is a (weak) integrity-of-execution concern.
- **影响:** A hostile BOF can cause the loader to patch section bytes with attacker-influenced values derived from the file's own header, rather than failing loudly. Constrained: the BOF is about to execute its own code anyway, so the practical privilege gain is nil; the value is in *detection* (a BOF that fails loudly is better than one that runs with subtly-corrupted relocations).
- **修复:** Optionally assert `reloc_ptr >= sec_table_end` and that the reloc window doesn't overlap the symbol table. Low priority; document as accepted permissiveness.

### [LOW] NEW — PE `rva_to_offset` final offset unbounded and u32 add can wrap on a synthetic image
- **位置:** `crates/pe/src/lib.rs:119`
- **状态:** NEW (dead crate — see INFO verdict below — so impact is contingent on revival)
- **已核验:** `return Some((rva - va + s.raw_ptr) as usize);` The `rva - va` leg is safe (guarded by `rva >= va` at `:118`), but `+ s.raw_ptr` is a u32 add with no overflow check — on a malformed PE with `raw_ptr` near `u32::MAX`, `rva - va + raw_ptr` wraps (release) / panics (debug). The returned offset is also not bounds-checked against `image.len()`; the consumers (`cstr_at:126`, `u32le:24`) do their own `.get()`, so no OOB read, but `cstr_at` computes `image.len() - off` which would underflow (wrapping sub on usize) if `off > image.len()` — except `cstr_at` guards `off >= image.len()` first (`:126`), so it returns `""` instead. Net: no panic, but a malformed `raw_ptr` yields a silently-wrong-but-empty resolution.
- **描述:** The comment at `:119` ("u32 + u32, in range") asserts infeasibility of overflow, which is true for a well-formed PE but not for the "tampered image" the function doc at `:38-39` says it must tolerate.
- **影响:** None in workspace builds (crate is `exclude`d). If revived, a malformed PE returns `None`/`""` rather than panicking, so this is robustness-only.
- **修复:** `Some(usize::try_from(rva - va).ok()?.checked_add(raw_ptr as usize)?)` and let the downstream `.get()` handle bounds. Trivial.

### [LOW] 07-08 minidump stale-comment, evasion SSN-add, resolver size-cap — OUT OF DOMAIN
- These three 07-08 LOWs live in `minidump-assembler`, `evasion`, `offset-resolver` — not in this domain. Listed only for completeness; not re-verified here.

---

## INFO — verified-clean areas (with evidence)

- **`crates/config` crypto core (`config/src/lib.rs:45-79`)** — Sound. `encrypt` draws fresh OsRng 32B key + 12B nonce (`:49-50`); ChaCha20-Poly1305 AEAD with empty AAD; `decrypt` (`:68-79`) verifies the Poly1305 tag and panics on mismatch — acceptable because all material is compile-time-baked, so a tag failure means tampering and the implant correctly treats it as fatal. The `ciphertext_is_real_and_key_bound` test (`:91-110`) pins that a wrong key is rejected. The `+9`-line diff this pass only touched the module doc (honest "obfuscation not confidentiality" boundary, `:10-14`) — no logic change. The AEAD itself is not the problem; the problem is key placement (CRIT-NEW-3 above).

- **`crates/config-macros` new code (`resolve_key`/`parse_hex_key`/`hex_digit`, `:143-192`)** — Sound in isolation. `parse_hex_key` guards `s.len() != 64` first (`:167`), so `chunks(2)` always yields exactly 32 pairs — `pair[0]`/`pair[1]` (`:175-176`) cannot OOB. `hex_digit` is total over its match. Malformed `NYX_CONFIG_KEY` surfaces as a clean compile error at the call site via `syn::Error::new(lit.span(), …)` (`:68-72`), not a proc-macro panic — so a bad env var cannot break `cargo build` with an ICE. The `encrypt(plain, key)` refactor (`:127-141`) correctly takes the key as a parameter and still draws a fresh nonce per call, preserving no-nonce-reuse. The deprecated-warning mechanism (`:84-99`) is a legitimate stable-Rust technique and I verified it emits the intended `#[warn(deprecated)]` at each call site (built `cargo build -p nyx-config --tests`, saw 3 warnings). No new panics introduced; no key-management footgun *within the macro* (the footgun is that the macro is unused — see CRIT-NEW-3).

- **`crates/coff` parse hardening (`lib.rs:141-263`)** — Re-verified "cleanest crate" verdict; still holds. Every untrusted size/offset flows through `checked_add`/`checked_mul`: section table (`:158-161`), symbol table (`:169-173`), per-section (`:181-183`), per-reloc (`:209-211`), per-symbol (`:235-237`). The raw-bytes window is strict (`:198-206`): a `(raw_ptr, raw_size)` overrunning EOF returns `Truncated`, not a silent `&[]`; pinned by `section_raw_window_overrunning_eof_is_rejected` (`tests/coff.rs:157-167`). `nsym=0xFFFFFFFF` is rejected (`tests/coff.rs:169-183`). `apply()` (`:311-365`) bounds-checks every field write (`off+8`/`off+4 ≤ buf.len()` at `:336-339`, `:348-350`), resolves symbols by raw `Symbol::index` correctly skipping aux records (`:324-328`), and the `try_into().unwrap()` at `:343`/`:357` cannot panic because the slice length is exactly 8/4 (guaranteed by the preceding bounds check). Allocation amplification is bounded — a section declaring `nreloc=65535` with too little reloc data fails on the first unreadable entry (`data.get(ro..ro+10)` at `:212`), not after allocating 65535 entries. The three new LOWs above (ADDR32NB doc, NRELOC_OVFL, reloc_ptr overlap) are spec-completeness/robustness notes, not the wraparound/OOB/silent-truncation class — the hardening the 07-08 report praised is intact.

- **`crates/profile/src/lexer.rs` `scan_string` (`:110-192`)** — Re-verified sound. `\xNN` guard `if *i + 2 >= b.len()` (`:160`) is a correct off-by-two (rejects when fewer than 2 hex digits remain after the `x`); verified the `"\xAB" + EOF` boundary. Unterminated string (`:114-118`) and trailing backslash (`:127-131`) are clean `Err`. `hex_val`/`hex_pair` (`:194-205`) are total. Word scanning (`:70-89`) cannot infinite-loop: the `if i == start` guard (`:76`) catches the case where `is_delim(c)` is true for the start byte (advances `i` via the match arms before reaching the `_` arm, so `c` is always non-delim there). `MAX_DEPTH=64` recursion cap in the parser (`parser.rs:29,178-190`) uses `checked_add` and is well below the 8 MiB stack.

- **`crates/profile/src/transform.rs`** — Sound. base64/netbios/mask/prepend/append are invertible and the test suite pins round-trips (`:294-365`). `b64_decode` (`:202-224`) tolerates padding/whitespace and rejects non-alphabet bytes with `InvalidBase64`. `mask` is honestly documented as non-CS-interop (`:8-15`) — the FNV-1a-derived 4-byte key is self-consistent (decode reads the prepended key, `:269-278`). All arithmetic uses wrapping where appropriate (`fnv1a32` `:285`). The `b64_decode` leftover-bits drop (when `nbits < 8` at EOF) is benign under the same-engine round-trip contract.

- **`crates/profile/src/parser.rs`** — Sound. Context-sensitive `header "Cookie";` (1-arg terminator) vs `header "N" "V";` (2-arg statement) disambiguation is purely structural (`:174-200`: peek for `{` → block, else collect args until `;`) — needs no block-name awareness and handles both forms. Statement arg collection (`:201-213`) terminates on `;` or EOF.

- **`crates/profile/src/bin/c2lint.rs`** — Sound, trivial CLI. Exit codes match the doc (`0`/`1`/`2`), stdin `-` works. No logic surface to audit.

### INFO — dead-crate verdict: `crates/pe` (re-confirmed)

**Verdict: still dead. Recommend DELETE (or re-`members`-ify).** Unchanged from 07-08.

- `git diff crates/pe/src/lib.rs` is empty. Workspace `Cargo.toml` still `exclude = ["crates/pe"]`. `resolve_export` is used only by its own tests. The implant resolves symbols via `nyx-coff` / `nyx-implant-evasionsdk`. The code is well-written (every PE offset through `u16le`/`u32le` returning `Option`, `checked_add`/`checked_mul` throughout, `MAX_EXPORT_NAMES = 1<<20` ceiling at `:60-63`), but it does not compile in workspace builds and is silently bit-rotting. The one new LOW (`rva_to_offset` u32 add at `:119`) is contingent on revival. Same recommendation: delete, or re-add to `members` so CI type-checks it.

---

## Summary table

| Sev | Count | Headline |
|-----|-------|----------|
| CRITICAL | 1 | CRIT-NEW-3 PARTIALLY FIXED: doc honesty done, but `NYX_CONFIG_KEY` knob is wired only into the unused `embed!` macro; the real implant (`build.rs`) still bakes key+nonce+ct together and ignores the knob — operators given a false sense of per-build key control |
| HIGH | 0 | (07-08 HIGH `BeaconPrintf` overflow is out of domain, in `bof-runner`) |
| MEDIUM | 1 | MED-NEW-MISC2 STILL PRESENT: `set useragent` CRLF gap untouched (no diff to profile) |
| LOW | 6 | `terminator_of` last-vs-first + argless-drop (NEW); coff REL32 debug-arith (STILL); coff ADDR32NB doc/impl mismatch (NEW); coff no NRELOC_OVFL handling (NEW); coff reloc_ptr not range-checked (NEW); PE `rva_to_offset` u32 wrap (NEW, dead crate) |
| INFO | — | config AEAD core sound; config-macros new hex-parse/warning code sound in isolation; coff re-confirmed "cleanest crate"; profile lexer/parser/transform/bin sound; `pe` re-confirmed dead |

**What changed vs 07-08:** the config-macros/crypto docs are now honest (real improvement — the false "defeats 1768.py extractors" claim is gone, replaced by an accurate "obfuscation not confidentiality" boundary, plus a clever compiler-warning nudge). But the structural fix the plan called for (方案 A — key not in binary) did not happen for the production path, and the new `NYX_CONFIG_KEY` operator knob is effectively dead code because `embed!` is invoked only by tests. The one MEDIUM in this domain (useragent CRLF) was not touched at all. COFF remains the best-hardened crate in the set.
