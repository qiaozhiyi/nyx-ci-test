# client-cli — Deep Security Audit (2026-07-10 re-verification pass)

**Scope:** `crates/client-cli/src/` — main.rs, rest.rs, `tui/{mod,render,input,panes,config,session_meta,topology,credstore}.rs`, `theme.rs`, `parse.rs`, `types.rs`, `socks/{mod,handshake,relay,api}.rs`.

**Method:** Read `_CONTEXT.md` + 07-08 baseline. `git diff` every changed file in the domain (`handshake.rs` +159, `rest.rs` +59, `credstore.rs` +41, `socks/mod.rs` +26, `main.rs` +25, `relay.rs` +5). Ran `cargo test --bin nyx-cli` (147 passed, 0 failed) to investigate the "failing" test. Paged the large `tui/mod.rs` + `render.rs` rather than blind-reading. Every claim below cites a line I actually read.

**Headline:** The three P0/P1 security fixes (SOCKS auth, HTTP transport policy, creds-encrypt gate) landed and their unit tests pass — but **two of the three fixes are bypassable at runtime**, and the open-proxy fix is bypassable *by design*. Several 07-08 robustness findings (C-4/C-5/C-6/C-8) were NOT touched by the fix-pass and remain exactly as reported. The "currently-failing" test flagged in the brief now **passes**.

---

## [HIGH] CC-1 SOCKS5 non-loopback open-proxy fix is bypassable: auth-configured listener still serves clients that omit method 0x02

- **位置:** `socks/handshake.rs:72-84` (greeting method selection), `socks/mod.rs:90-97` (the run_socks guard).
- **状态:** PARTIALLY FIXED (P0-10 fix is real but has a design hole — NEW finding on the fix).
- **已核验:** `run_socks` (mod.rs:90-97) correctly refuses to *start* a non-loopback listener with no `socks_auth`: `if !is_loopback && socks_auth.is_none() { anyhow::bail!(...) }`. So a non-loopback bind now *requires* `--socks-user/--socks-pass`. Good. BUT the greeting negotiation then **falls back to NO-AUTH** whenever the client doesn't offer method `0x02`:
  ```rust
  let selected = if auth.is_some() {
      if methods.contains(&0x02) { 0x02 }
      else if methods.contains(&0x00) { 0x00 }   // <-- open-proxy bypass
      else { 0xFF }
  } else if methods.contains(&0x00) { 0x00 }
  else { 0xFF };
  ```
  (handshake.rs:72-84). When `selected == 0x00`, the function writes `[05][00]` and returns `Ok(())` **without ever calling `read_userpass_auth`** (the `if selected == 0x02` gate at line 90 skips it). This fallback is **explicitly tested as intended** (`greeting_falls_back_to_noauth_when_configured`, handshake.rs:312-322) and the doc comment (handshake.rs:52-56) documents it: *"fall back to 0x00 (NO AUTH) only if the client did not offer 0x02."*
- **描述:** Every SOCKS5 client in existence can choose which auth methods to *offer*. An attacker who wants to use the operator's beacon as an open proxy simply sends the greeting `[05][01][00]` (offers ONLY no-auth) — the bridge replies `[05][00]` and proceeds unauthenticated. The credentials the operator set with `--socks-user/--socks-pass` are never consulted. The `run_socks` guard only proves creds were *configured*, not that they are ever *required per-connection*. This is the exact open-proxy condition P0-10 was meant to prevent.
- **影响:** `nyx-cli socks --listen 0.0.0.0:1080 --socks-user op --socks-pass x` is still a fully open proxy to any peer that can reach port 1080 — the operator believes it is auth-gated (the `[socks] … auth: user/pass (RFC 1929)` log line at mod.rs:122-129 says so) but it is not. The fix creates a **false sense of security**, which is worse than the original honest "no auth" because operators will now expose the listener believing it is protected.
- **修复:** On a non-loopback bind, the NO-AUTH fallback must be removed entirely. The correct policy is: `auth = Some(_)` (non-loopback) → select `0x02` if offered, else `0xFF` (reject). Drop the `else if methods.contains(&0x00)` branch when `auth.is_some()`. (If an operator genuinely wants a no-auth loopback listener, that's the `auth = None` path, which is unaffected.) Also delete / invert the `greeting_falls_back_to_noauth_when_configured` test, since it currently asserts the insecure behavior is correct.

---

## [HIGH] CC-2 HTTP transport policy (P1-9) is not enforced on the runtime `/connect` path — only on the initial `--server` URL

- **位置:** `rest.rs:363-398` (`enforce_http_policy`), `rest.rs:407-421` (the single call site, inside `spawn`), `rest.rs:513-517` (`Cmd::Connect` — NO policy check), `tui/mod.rs:1417-1429` (`/connect` command).
- **状态:** PARTIALLY FIXED (P1-9 gates the launch URL but is trivially bypassed at runtime — NEW finding on the fix).
- **已核验:** The new `enforce_http_policy` (rest.rs:363-398) is sound in isolation: it parses the authority, handles `[ipv6]:port`, recognizes `127.0.0.1`/`::1`/`localhost` as loopback, warns, and refuses non-loopback `http://` unless `NYX_ALLOW_HTTP=1`. But it is called **exactly once**, at worker-thread startup (rest.rs:410):
  ```rust
  std::thread::spawn(move || {
      if let Err(reason) = enforce_http_policy(&server) { … return; }
  ```
  The `Cmd::Connect(s, t)` arm (rest.rs:513-517) does `server = Some((s, t));` with **no policy check**:
  ```rust
  Cmd::Connect(s, t) => {
      log_push(&mut log_buf, &format!("connecting to {s} …"), Level::Info);
      server = Some((s, t));
      connect_changed = true;
  }
  ```
  And the TUI `/connect` command (mod.rs:1417-1429) forwards any URL straight through: `self.send(Cmd::Connect(url, token));`.
- **描述:** An operator can launch the TUI against a safe loopback URL (`nyx-cli`, default `http://127.0.0.1:8443`) — passing the gate — then from inside the TUI run `/connect http://teamserver.example:8443 <token>` and the bearer token + any `/creds?reveal=1` pull traverse plaintext HTTP with no warning and no refusal. This is the exact scenario C-2 (07-08) described; the fix closes the front door and leaves the back door open.
- **影响:** Same as original C-2: a network-positioned observer on the operator→team-server path captures the bearer token (full `/api/*` operator capability) and any revealed credentials. The fix's value is limited to operators who only ever use `--server` and never `/connect`.
- **修复:** Call `enforce_http_policy(&s)` inside the `Cmd::Connect` arm (rest.rs:513) and, on `Err`, `log_push` the reason at `Level::Err` and leave `server` unchanged. (The error message is already user-friendly.)

---

## [HIGH] CC-3 (re-verify C-1) Plaintext credential storage — stopgap gate added, but encryption NOT implemented and the gate is off by default

- **位置:** `tui/credstore.rs:94-106` (new `NYX_CREDS_ENCRYPT` gate in `save_to`), `tui/credstore.rs:34-39` (`refuse_plaintext`), `tui/credstore.rs:125-129` (still `serde_json::to_vec_pretty` of plaintext `secret`).
- **状态:** PARTIALLY FIXED (07-08 C-1).
- **已核验:** The fix adds a clear SECURITY doc comment (credstore.rs:9-17) admitting plaintext-at-rest and a `NYX_CREDS_ENCRYPT=1` opt-in gate (credstore.rs:99-106) that refuses persistence:
  ```rust
  let env_val = std::env::var("NYX_CREDS_ENCRYPT").ok();
  if refuse_plaintext(env_val.as_deref()) {
      return Err(std::io::Error::other("NYX_CREDS_ENCRYPT=1 is set: refusing …"));
  }
  ```
  Pure-logic test `refuse_plaintext_gate_logic` (credstore.rs:491-500) covers `None`/`""`/`"0"`/`"1"`/`"yes"`. The chmod-0600-fail-closed logic (credstore.rs:149-172) and atomic temp+rename (credstore.rs:131-173) are intact and correct.
- **描述:** The actual encryption layer (OS keychain / argon2id passphrase → AEAD) called for in 07-08 C-1 was **not implemented**. The fix is documentation + an opt-out-by-default gate. Out-of-box, secrets still hit `~/.nyx/creds.json` as `"secret": "P@ssw0rd"` in cleartext. The gate also has a UX trap: it errors *at save time* (`save_to` returns `Err`), so an operator who set `NYX_CREDS_ENCRYPT=1`, runs `/creds sync reveal`, and the save fails — they get an error in the log but the in-memory `self.creds` was already populated, so the secrets are in process memory and the next `/creds export` works fine; the gate only blocks *persistence*, not *use*. That's arguably the right granularity, but it should be loud.
- **影响:** Unchanged from 07-08 C-1 for the default-config operator: backups/sync/EDR/forensic imaging recover the full vault in cleartext. Only operators who set the env var are protected (and then only by refusing to persist, which forces server-side creds).
- **修复:** Ship the encryption layer (the comment already names the right primitives: argon2id passphrase → XChaCha20-Poly1305, or OS keychain). At minimum: warn loudly on first ingest when persistence is plaintext, and make `NYX_CREDS_ENCRYPT=1` also clear `self.creds` in memory after the refused save so the gate is consistent.

---

## [HIGH] CC-4 (re-verify C-2 default) Bearer token over plaintext HTTP — P1-9 default-server exposure note

- **位置:** `main.rs` (default server URL), `rest.rs:363-398` (policy).
- **状态:** PARTIALLY FIXED (supplements CC-2).
- **已核验:** `enforce_http_policy` correctly treats the default loopback URL as allowed. The remaining exposure is CC-2 (the `/connect` bypass) plus the fact that `NYX_ALLOW_HTTP=1` is a permanent process-wide opt-out with no per-request warning after the first.
- **描述 / 影响 / 修复:** See CC-2. Additionally: once `NYX_ALLOW_HTTP=1` is set, *every* subsequent connection (including `/connect` to new hosts) is silently plaintext — consider warning per-connection rather than once at startup.

---

## [MEDIUM] CC-5 (re-verify C-8) `rest::short()` still byte-slices — worker-thread panic on crafted `SessionView.id`

- **位置:** `rest.rs:2260-2262`.
- **状态:** STILL PRESENT (07-08 C-8, untouched by the fix pass).
- **已核验:** `fn short(s: &str) -> &str { &s[..s.len().min(8)] }` — unchanged. Called on `session` ids throughout the worker (rest.rs:531, 562, 594, 767, 808, 837, …, 1899, 1907). `SessionView.id` is a free-form `String` from the server (`crates/rest/src/lib.rs`). The safe char-based `short()` in `tui/mod.rs` was not reconciled with this copy.
- **描述 / 影响 / 修复:** A `SessionView.id` whose first 8 bytes land mid-UTF-8-codepoint (e.g. an id beginning with a multi-byte char) panics the worker thread on the first `log_push` that wraps the id. Same fix as 07-08: `s.chars().take(8).collect::<String>()`.

---

## [MEDIUM] CC-6 (re-verify C-4) Server-controlled session list — unbounded growth + `as u16` render truncation

- **位置:** `rest.rs:2264-2277` (`session_signature`), `tui/render.rs:253` and `:751` (`let row_y = area.y + i as u16;`).
- **状态:** STILL PRESENT (07-08 C-4, untouched).
- **已核验:** `session_signature` still concatenates `id|hostname|username|is_admin|pending;` per row into one `String` (rest.rs:2264-2277). Render still does `let row_y = area.y + i as u16; if row_y >= area.y + area.height { break; }` at render.rs:253 and :751. No client-side row cap on `self.sessions`.
- **描述 / 影响 / 修复:** Unchanged from 07-08: a malicious/buggy team server flooding >65 536 rows wraps `i as u16`, the break guard stops firing, the render loop re-sweeps the first ~65k rows indefinitely (CPU spin + visual corruption); `session_signature` allocates a multi-MB string per poll. Fix: cap the list client-side, use `u32`/`usize` row math, hash the signature.

---

## [MEDIUM] CC-7 (re-verify C-5) `/upload`, `/bof`, `/inject` read whole file into RAM with no size cap

- **位置:** `tui/mod.rs:1526-1544` (`/bof`), `:1546-1582` (`/upload`), `:1799-1844` (`/inject`).
- **状态:** STILL PRESENT (07-08 C-5, untouched).
- **已核验:** All three still do `std::fs::read(&file)` → `Vec<u8>` → `hex::encode(&data)` (doubles size into a `String`) → JSON body, on the UI thread, with no size guard.
- **描述 / 影响 / 修复:** Unchanged from 07-08: operator typo (`/upload /var/log/huge.log`) → OOM + TUI freeze (sync IO on UI thread). Add a size cap and move the read+hex off the UI thread.

---

## [MEDIUM] CC-8 (re-verify C-6) Download `local` path still unsandboxed; `create_dir_all` mints arbitrary dirs

- **位置:** `rest.rs:1875-1896` (`finish_chunked`).
- **状态:** STILL PRESENT (07-08 C-6, untouched).
- **已核验:** `let sp = match local { Some(l) if !l.trim().is_empty() => l.clone(), _ => … }` (rest.rs:1876-1882) takes the operator's `local` verbatim; `let _ = std::fs::create_dir_all(parent)` (rest.rs:1893); `std::fs::write(&save_path, &out)` (rest.rs:1896) writes attacker-controlled (beacon-side) bytes to that path.
- **描述 / 影响 / 修复:** Unchanged from 07-08: `/download C:\x ../../.bashrc` writes beacon-controlled bytes to an arbitrary local path; `create_dir_all` silently mints `../../.ssh/` etc. Canonicalize, confine to a downloads root, and use `O_CREAT|O_EXCL` to refuse existing/symlink targets.

---

## [MEDIUM] CC-9 SOCKS handshake DoS surface unchanged — unbounded `tokio::spawn` per TCP connection, no in-flight handshake cap, no per-source rate limit

- **位置:** `socks/mod.rs:133-142` (accept loop), `socks/relay.rs:58-65` (`handle_conn` entry), `socks/relay.rs:77-85` (cap is post-handshake).
- **状态:** STILL PRESENT (folded into 07-08 C-3 part (c); NOT addressed by P0-10).
- **已核验:** The accept loop (mod.rs:135-139) `tokio::spawn`s a task per inbound TCP connection with no semaphore: `Ok((stream, peer)) => { … tokio::spawn(async move { relay::handle_conn(stream, c).await; }); }`. The `max_chan` cap (relay.rs:78) runs **after** `read_greeting` + `read_request` (relay.rs:60-69), so it limits *open channels*, not *handshake-phase tasks*. `handle_conn` performs the full handshake (including, for an auth-configured listener, the RFC 1929 sub-negotiation reads) before the cap check.
- **描述 / 影响 / 修复:** A TCP-connection flood to the listener spawns unbounded handshake tasks (each doing network reads with `tokio::io` defaults — no per-connection read deadline), exhausting task slots / file descriptors. The new auth code makes this slightly *worse* (more await points before the cap). Fix: bound in-flight handshakes with a `tokio::sync::Semaphore` acquired in the accept loop and released after `handle_conn`'s cap check; add per-source-IP connection rate limiting; set an explicit read timeout on the handshake phase.

---

## [LOW] CC-10 `enforce_http_policy` scheme match is case-sensitive — `HTTP://` and mixed-case schemes skip the check

- **位置:** `rest.rs:365` (`if !s.starts_with("http://")`).
- **状态:** NEW (finding on the P1-9 fix).
- **已核验:** `s.starts_with("http://")` is case-sensitive. A URL written as `HTTP://evil.example:8443` (or `Http://`) does not match → the function returns `Ok(())` at line 366 ("https:// or schemeless — not the plaintext-HTTP case") and applies **no check**. Whether this is exploitable depends on `reqwest`'s scheme normalization (reqwest lowercases schemes internally before dispatch, so `HTTP://` is still dispatched as plaintext HTTP).
- **描述 / 影响:** An operator (or a pasted URL) using an uppercase scheme bypasses the plaintext-HTTP refusal. Low severity because (a) reqwest still treats it as HTTP, so the token *does* traverse plaintext — the bypass is real, just unusual to hit by accident; (b) the `/connect` bypass (CC-2) already makes this gate advisory.
- **修复:** Lowercase the scheme before comparing: `s.to_ascii_lowercase().starts_with("http://")`, or parse with the `url` crate and inspect `scheme()`.

---

## [LOW] CC-11 (re-verify C-7) `worker_loop` still `.expect()`s the reqwest client build

- **位置:** `rest.rs:495-496` (the `.expect("reqwest client build")` moved with the code; verify current line).
- **状态:** STILL PRESENT (07-08 C-7, untouched).
- **已核验:** `grep` confirms `expect("reqwest client build")` is still present in rest.rs (line 496 region). On the worker thread, not the UI thread.
- **描述 / 影响 / 修复:** Unchanged from 07-08: a TLS-backend init failure panics the worker; TUI surfaces "command dropped" instead of a clean exit. Bubble the error via the initial snapshot like the runtime-build path does.

---

## [LOW] CC-12 (re-verify C-10) `focused_state`/`focused_state_mut` final `.expect()` while terminal is in raw mode

- **位置:** `tui/mod.rs` (the `focused_state`/`focused_state_mut` pair).
- **状态:** STILL PRESENT (07-08 C-10, untouched — confirm exact current lines).
- **描述 / 影响 / 修复:** Unchanged from 07-08: latent panic wedges the terminal in raw mode. Return `Option` and degrade, or install a panic hook that restores the terminal.

---

## [LOW] CC-13 (re-verify C-11) Dead `_ =>` divide-by-zero branch in `render_table`/`render_borderless_table`

- **位置:** `tui/render.rs:457` and `:978`.
- **状态:** STILL PRESENT (07-08 C-11, untouched).
- **已核验:** `100 / header.len() as u16` — if a future caller passes an empty header, integer divide by zero. Dead today.
- **修复:** Guard `_ if header.is_empty() => Vec::new()`.

---

## [LOW] CC-14 (re-verify C-12) `config.json` still written without 0600

- **位置:** `tui/config.rs` (`save()`).
- **状态:** STILL PRESENT (07-08 C-12, untouched).
- **描述:** Inconsistent with credstore's strict 0600. Holds no secrets today; defense-in-depth gap.

---

## [LOW] CC-15 (re-verify C-13) `$HOME` unset → silent cwd fallback for credstore/config/session_meta

- **位置:** `tui/credstore.rs:274-279` (`home_dir`), `tui/config.rs`, `tui/session_meta.rs`.
- **状态:** STILL PRESENT (07-08 C-13, untouched).
- **已核验:** `home_dir()` (credstore.rs:274-279) still returns `PathBuf::from(".")` when `$HOME` is unset. The three modules still disagree on the fallback (credstore → `.`; config/session_meta → `./.nyx/…`).
- **描述 / 影响 / 修复:** Under launchd/cron/containers without `HOME`, plaintext creds land in cwd silently. Use `dirs::home_dir()` / `getpwuid_r`; share one `nyx_home()`.

---

## [INFO] Flagged "currently-failing" test `sessionlist_current_row_has_highlight_background` PASSES

- **位置:** `tui/mod.rs:2797-2847`.
- **已核验:** Ran `cargo test --bin nyx-cli sessionlist_current_row_has_highlight_background` — **`test result: ok. 1 passed`** — five times in a row (no flakiness), and the full suite `cargo test --bin nyx-cli` → **147 passed; 0 failed**. The test sets two sessions, binds the focused pane to the first (`aaaa1111aaaa`), renders, and scans `buf[(5,y)]` for a cell whose `bg == theme::accent_dim()`. That succeeds because `theme::selected().bg == p.accent_dim` (theme.rs:262-268) and `render_sessions_in_pane` fills the current row to full width with `sel_bg` (render.rs:296-305, the `pad` Span). The highlight-fill code is what makes the test pass; before that fix the bg only covered the content spans, not `x=5`'s neighborhood reliably.
- **结论:** The "currently-failing" premise in the audit brief is stale — this test is green. No action needed. (If it was observed failing in some other run, the most likely cause is shared global theme state: `theme_switch_changes_active_palette` (mod.rs:2850-2858) mutates the process-global `OnceLock<RwLock<Palette>>` and restores to "mocha" at the end — a test that asserts an `accent_dim` color running concurrently or after a failed restore could see Cyan instead of the mocha value. But under the default serial test runner it does not reproduce.)

---

## 已验证干净的区域 (checked and sound)

- **No local command execution on the operator host — re-verified.** `run_shell` (mod.rs:1067-1081) sends `Cmd::Shell { args, … }` to the worker and never touches `Command::new`/`exec`. `grep` for `Command::new`/`process::Command`/`exec` across `tui/input.rs` + `tui/mod.rs` returns only `crossterm::execute!` (terminal control, unrelated). Every meta-command constructs JSON bodies via `serde_json::json!`. Unchanged from 07-08.
- **No `unsafe` anywhere in client-cli — re-verified.** `grep -rn "unsafe" crates/client-cli/src/` → no hits. `crates/rest` carries `#![forbid(unsafe_code)]` (lib.rs:15).
- **No TLS verification weakening — re-verified.** `grep` for `danger_accept_invalid_certs`/`min_tls`/`redirect::Policy` across client-cli + rest → no hits. The default reqwest client does the right thing for `https://`.
- **SOCKS5 wire parsing is bounds-safe — re-verified incl. the new auth code.** All length-prefixed reads use `read_u8()`/`read_u16()`/`read_exact()`; `nmethods`, `ulen`, `plen`, and the domain length are all `u8` (≤255), so no unbounded allocation (handshake.rs:68-70, 115-120, 157-159). RFC 1929 version check is correct (`ver != 0x01` → fail at handshake.rs:110-114). Port is `read_u16()` big-endian (handshake.rs:173). Reply ordering for the auth-failure path is correct: `[05][02]` method-select is written (handshake.rs:86) *before* `[01][01]` status (handshake.rs:123), matching what the rejecting test drains (handshake.rs:302-309).
- **Bearer tokens / secrets still never logged — re-verified.** `FetchCreds` logs only the count (rest.rs:1399-1404); `/connect` logs only the URL (mod.rs:1427); the new `enforce_http_policy` warning logs only the host, never the token. The masking in display paths (input.rs:532 `mask()`, applied at render.rs:372 and :830) is unchanged.
- **Credstore write is atomic + fail-closed on chmod — re-verified.** temp+rename (credstore.rs:131-173); on `set_permissions(0600)` failure the temp is `remove_file`'d and `Err` returned (credstore.rs:158-165) — no world-readable plaintext left behind. Dir is best-effort 0700 (credstore.rs:116-123). This part of credstore is solid; only the encryption-at-rest layer is missing (CC-3).
- **The SOCKS auth fix's *mechanics* are correct where they apply.** `read_userpass_auth` validates `ver==0x01`, bounds reads to u8, compares both fields, writes the right status byte, and bails on mismatch (handshake.rs:105-128). The non-constant-time compare is explicitly justified in the doc comment (handshake.rs:102-103). The bug is purely the policy decision to fall back to 0x00 (CC-1), not the RFC 1929 implementation.
- **`main.rs` socks-auth argument pairing is sound.** `(Some(u), Some(p)) | (None, None)` with a bail on the mixed case (main.rs:73-80) prevents a lone `--socks-user` misconfiguration. The `run_socks` non-loopback guard (mod.rs:90-97) is a correct second line of defense.

---

## Summary table

| ID | Sev | 状态 | Area | One-liner |
|----|-----|------|------|-----------|
| CC-1 | HIGH | NEW (on fix) | socks/handshake.rs:72-84 | Non-loopback open-proxy fix bypassable: client omitting method 0x02 gets NO-AUTH |
| CC-2 | HIGH | NEW (on fix) | rest.rs:513-517 | HTTP policy only enforced at spawn, not on runtime `/connect` |
| CC-3 | HIGH | PARTIALLY FIXED | credstore.rs:94-106 | Plaintext creds: gate added but off by default; no encryption layer |
| CC-4 | HIGH | PARTIALLY FIXED | rest.rs:363 | Bearer-over-HTTP: gate added; default safe; bypassed via CC-2 |
| CC-5 | MED | STILL PRESENT | rest.rs:2260 | `short()` byte-slice panics on multibyte `SessionView.id` |
| CC-6 | MED | STILL PRESENT | render.rs:253,751; rest.rs:2264 | Session-list unbounded + `i as u16` render truncation |
| CC-7 | MED | STILL PRESENT | tui/mod.rs:1526,1566,1824 | `/upload`/`/bof`/`/inject` no size cap, sync IO on UI thread |
| CC-8 | MED | STILL PRESENT | rest.rs:1875-1896 | Download `local` unsandboxed; `create_dir_all` mints dirs |
| CC-9 | MED | STILL PRESENT | socks/mod.rs:135-139 | Unbounded handshake `spawn`; no per-source rate limit |
| CC-10 | LOW | NEW (on fix) | rest.rs:365 | `enforce_http_policy` scheme match case-sensitive (`HTTP://` skips) |
| CC-11 | LOW | STILL PRESENT | rest.rs:496 | `.expect()` on reqwest build panics worker |
| CC-12 | LOW | STILL PRESENT | tui/mod.rs | `focused_state` `.expect()` in raw mode |
| CC-13 | LOW | STILL PRESENT | render.rs:457,978 | Dead `_ =>` divide-by-zero on empty header |
| CC-14 | LOW | STILL PRESENT | tui/config.rs | `config.json` no 0600 |
| CC-15 | LOW | STILL PRESENT | credstore.rs:274 | `$HOME` unset → cwd fallback |
| INFO | — | RESOLVED | tui/mod.rs:2797 | Flagged failing test actually passes (147/147 green) |

**Top 2 to fix first:** CC-1 (the open-proxy fix is actively misleading — remove the `0x00` fallback when `auth.is_some()`) and CC-2 (call `enforce_http_policy` in the `Cmd::Connect` arm). Both are small, surgical edits to the fix-in-progress.
