# Nyx Transport Layer — Line-by-Line Security Audit (2026-07-10)

**Scope:** `crates/transport/src/` — `lib.rs`, `traits.rs`, `tls.rs`, `h2.rs`, `doh_dns.rs`, `slack_api.rs`, `llm_api.rs`, `mcp.rs`, `webtransport.rs`, `smb_pipe.rs`, `malleable.rs`, `emitter.rs`.
**Method:** static review; every line citation verified against current working-tree source (with uncommitted `git diff` applied). No formatters/linters/test-suites run.
**Baseline:** `docs/audit_2026_07_08/transport.md` (22 prior findings: MED-11, LOW-11, LOW-12, HIGH-NEW-T1..T4, MED-NEW-T5..T10, LOW-NEW-T11..T17).

## Fix-in-progress delta (what changed since 07-08)

`git diff --stat crates/transport/` shows 5 files touched; the other 6 domain files are **byte-identical** to the 07-08 baseline:

| File | Delta | Nature of change |
|------|-------|------------------|
| `doh_dns.rs` | +47 | T1 fix: `STANDARD` → `URL_SAFE_NO_PAD` base64 + 2 new tests |
| `mcp.rs` | +74 | T4 partial fix: added optional `api_key: Option<String>` + `Authorization: Bearer` header + 2 new tests |
| `smb_pipe.rs` | +3 | T2 fix: dropped `FILE_FLAG_OVERLAPPED`, opened with `0` (synchronous) |
| `emitter.rs` | +7 | T3 partial fix: added `⚠ NOT WIRED` doc banner |
| `lib.rs` | +5 | T3 partial fix: doc comment on `pub mod emitter` |
| `traits.rs`, `llm_api.rs`, `slack_api.rs`, `malleable.rs`, `tls.rs`, `h2.rs`, `webtransport.rs` | 0 | **unchanged** |

The fact that `traits.rs` (T6), `slack_api.rs` (T7), `llm_api.rs` (T5/T8/T13/T14/T16), and `malleable.rs` (T9/T10/LOW-11) have zero diff is itself a finding: the bulk of the transport bug list was not touched in this fix pass.

---

## Part 1 — Re-verification of prior findings

### [HIGH] HIGH-NEW-T1 — DoH base64 `+`/`/` as DNS labels → **FIXED**
- **位置:** `crates/transport/src/doh_dns.rs:29` (`use ... URL_SAFE_NO_PAD as BASE64`), `:206` (`BASE64.encode(chunk)`), `:250` (`BASE64.decode(&txt_data)`)
- **状态:** FIXED
- **已核验:** the diff swaps `general_purpose::STANDARD` for `general_purpose::URL_SAFE_NO_PAD` at line 29. The URL-safe-no-pad alphabet (`A-Za-z0-9-_`, no `=`) is a strict subset of RFC 1035 §2.3.4 DNS-label characters (letters/digits/hyphen; `_` is technically not in the LDH rule but is universally accepted by resolvers and is what real DNS-tunnellers like iodine/dnscat2 emit). `send` (line 206) and `recv` (line 250) both use the same engine, so the round-trip is consistent.
- **Fix-quality audit:** the fix is correct at the encoding layer. Two new tests (`url_safe_base64_emits_only_dns_label_chars`, `build_query_name_all_dns_label_safe`) exercise the full `0x00..=0xFF` byte range and assert every output char is DNS-label-safe, plus a round-trip decode. This is a genuine test of the fix, not a tautology. **However** the fix is *incomplete* on two counts (see NEW-MED-T19 and NEW-LOW-T18 below): (a) `build_query_name` still has no total-name-length (253-byte) guard, so a long C2 domain + full-size chunk can still overflow; (b) the module doc comment at line 38-40 still claims "160 raw bytes → ~216 base64 chars" — actual is **214** chars (verified: `ceil(160/3)*4 = 216`, minus 2 padding chars dropped by no-pad = 214). Cosmetic, but a stale invariant in a security-sensitive comment.

### [HIGH] HIGH-NEW-T2 — SMB overlapped handle used sync → **FIXED**
- **位置:** `crates/transport/src/smb_pipe.rs:244` (now `0` instead of `FILE_FLAG_OVERLAPPED`), constant removed at line 29
- **状态:** FIXED (root cause addressed; residual robustness issues remain — see NEW-MED-T20)
- **已核验:** the diff deletes `pub const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;` and changes the `CreateFileW` `dwFlagsAndAttributes` argument from `FILE_FLAG_OVERLAPPED` to `0` with an inline comment explaining the synchronisation contract. `write_all` (line 273) and `read_exact` (line 295) still pass `std::ptr::null()` as `lpOverlapped`, which is now **correct** for a synchronous handle (MSDN: a handle opened *without* `FILE_FLAG_OVERLAPPED` requires `lpOverlapped = NULL`). The mode mismatch that caused `ERROR_INVALID_PARAMETER` is gone.
- **Fix-quality audit:** root-cause fixed, not symptom-patched. The simpler of the two options recommended in the 07-08 report was taken (drop overlapped, keep blocking I/O) — correct choice given the existing `thread::sleep(10ms)` retry loop in `read_exact` matches blocking semantics. Residual issues (busy-spin on broken pipe, no `GetLastError` distinction) are tracked as NEW-MED-T20.

### [HIGH] HIGH-NEW-T3 — FingerprintEmitter dead code; all HTTPS emits default JA3 → **PARTIALLY FIXED (documented, not wired)**
- **位置:** `crates/transport/src/emitter.rs:1-7` (new banner), `crates/transport/src/lib.rs:32-36` (new doc on `pub mod emitter`)
- **状态:** PARTIALLY FIXED — the *honesty* gap is closed; the *functional* gap is unchanged.
- **已核验:** both the module-level doc (`//! ⚠ NOT WIRED (P1-14)...`) and the re-export comment (`/// ⚠ NOT WIRED (P1-14)...`) now explicitly state that no transport calls `best()`, that all HTTPS traffic uses the default rustls `ClientHello`, and that operators must not assume outbound JA3 is controllable. Workspace grep for `FingerprintEmitter|emitter::best|Profile::Chrome|Profile::Firefox` still returns matches **only** inside `emitter.rs` (definition + tests) and `lib.rs` (module decl + doc) — confirmed no transport constructor references it. Every HTTPS channel (`slack_api.rs:82`, `llm_api.rs:58`, `doh_dns.rs:92`, `mcp.rs:77`, `malleable.rs:98`) still builds its client with the default builder.
- **Severity re-assessment:** the original HIGH was justified by "operators rely on cover they don't have." The documentation now closes that reliance gap — an operator reading the crate docs will *not* be misled. The underlying detection-surface risk (all Nyx outbound HTTPS is trivially JA3-fingerprintable as "rustls client", which is the exact failure mode this crate exists to prevent) is **unchanged**. I am keeping this at HIGH because the crate's stated #1 purpose (lib.rs:3-5: *"The #1 way modern C2 traffic is caught at the edge is fingerprinting the transport"*) is still unimplemented for every real channel; the doc banner turns a silent lie into an honest TODO, which reduces operator-deception severity but not detection severity. Downgrade to MED only when at least one channel is wired or the crate README front-loads this limitation.
- **修复:** unchanged from 07-08: thread the emitter into transport client construction, or gate the "blending" marketing behind a feature flag that is honestly off-by-default.

### [HIGH] HIGH-NEW-T4 — MCP unauthenticated; session_id is only credential → **PARTIALLY FIXED**
- **位置:** `crates/transport/src/mcp.rs:52-61` (struct), `:72` (`new` signature), `:111-113` (`auth_header`), `:128-130` (header injection), `:208`, `:223` (session_id still in arguments)
- **状态:** PARTIALLY FIXED
- **已核验:** the diff adds an `api_key: Option<String>` field and an `auth_header()` helper that returns `Some("Bearer <key>")` when set. `rpc_call` (line 123-130) breaks the ureq builder chain so the `Authorization` header is added only when an API key is configured. Two new unit tests assert the header contract (`auth_header_none_without_api_key`, `auth_header_bearer_with_api_key`).
- **Why partial, not fixed:**
  1. **The credential is optional and defaults to `None`.** `McpTransport::new` takes `api_key: Option<String>`, so any caller that passes `None` (or the existing callers, if any, that haven't been updated) gets a channel with **zero** authentication — exactly the 07-08 state. There is no compile-time or runtime enforcement that an api_key is required for production use. The fix adds a *capability* without making it the *default*.
  2. **No caller in the workspace passes an api_key.** Workspace grep for `McpTransport::new` outside `mcp.rs` returns **zero** matches — the channel is not constructed anywhere yet. So the "fix" is unverified against a real wiring; when someone does construct it, nothing forces them to supply a key.
  3. **The bearer token rides the same channel as the session_id.** Without TLS certificate pinning (still absent — see INFO section), a passive MITM of one request captures both the `session_id` *and* the `Authorization: Bearer` header, then replays them. The fix raises the bar from "guess/know a string" to "sniff one request," but on an unauthenticated or MITM-able network the channel is still fully readable/writable by an observer. The 07-08 report's core point ("never rely on session_id alone for authorization") is addressed; the deeper point ("correlate by an unauthenticated field on an unauthenticated transport") is not.
  4. **No entropy/length validation on the api_key.** `new` stores it verbatim. An operator-supplied `"x"` is accepted as a bearer token.
  5. **`session_id` is still sent in the cleartext JSON `arguments`** (line 208, 223) alongside the now-encrypted transport — redundant correlation data that an observer still gets.
- **影响:** the channel can now be authenticated, but only if the operator remembers to supply a key and only against an on-path attacker who cannot see the TLS traffic. For the default `None` case the original HIGH (frame injection / tasking theft by anyone who learns the session_id) is fully intact.
- **修复:** (a) make `api_key: String` (not `Option`) required in the production constructor, or split into `new_unauthenticated` (test-only) vs `new` (requires key); (b) add a min-length/entropy floor on the key; (c) document that bearer-over-TLS-without-pinning is still sniffable by an active MITM with a trusted CA; (d) ideally HMAC the JSON-RPC body keyed by an ECDH-derived secret so the server authenticates each request, not just the connection.

### [MED] MED-NEW-T5 — LLM recv broken + XOR leaks to provider → **STILL PRESENT**
- **位置:** `crates/transport/src/llm_api.rs:83-91` (single-turn body), `:198-218` (`recv`), `:74-79` (`xor_frame`), `:33-35` (placeholder doc)
- **状态:** STILL PRESENT (file has zero diff)
- **已核验:** unchanged. `post_message` still builds `{"messages":[{"role":"user","content":content}]}` — single-turn, no `system`, no conversation history, no session id passed to the API. `recv` (line 204) calls `post_message(RECV_PROMPT, 200)` where `RECV_PROMPT = "continue the debug log analysis — output the hex block exactly as shown in the session"`; with no history the Messages API has no "session" to continue and will hallucinate. `xor_frame` (line 74-79) still XORs with a repeating 32-byte key; the doc comment at line 33-35 still self-identifies as a *"placeholder — real key exchange belongs at the protocol layer."* The XOR ciphertext is still POSTed to `api.anthropic.com` as prompt text (line 190-193).

### [MED] MED-NEW-T6 — init_all never marks channel healthy on success → **STILL PRESENT**
- **位置:** `crates/transport/src/traits.rs:96-102`
- **状态:** STILL PRESENT (`traits.rs` has zero diff)
- **已核验:** `init_all` body is verbatim:
  ```rust
  for slot in &mut self.channels {
      if let Err(_e) = slot.transport.init() {
          slot.healthy = false;
      }
  }
  ```
  The `Ok` branch does nothing; `healthy` stays at its `register()` default of `false` (line 85). Combined with the fallback guard at line 130 (`if !slot.transport.requires_probe() || slot.healthy`), a freshly-initialised stack only ever falls back to channels with `requires_probe() == false` — i.e. only `MalleableTransport` (`malleable.rs:358-360`). DoH/Slack/LLM/MCP/SMB/WebTransport are all skipped until a `probe_health()` tick happens to flip one to healthy.
- **Note:** the companion backoff issue (MED-11, fallback loop at `traits.rs:128-146` has no sleep/cooldown) is also still present and still untouched.

### [MED] MED-NEW-T7 — one poison message permanently blocks Slack recv → **STILL PRESENT**
- **位置:** `crates/transport/src/slack_api.rs:210-216`
- **状态:** STILL PRESENT (`slack_api.rs` has zero diff)
- **已核验:** `poll_history` still does:
  ```rust
  let frame = base64::...::STANDARD
      .decode(&msg.text)
      .map_err(|_| TransportError::Transient("Slack message: bad base64"))?;
  // Advance the cursor.
  self.last_ts = Some(msg.ts.clone());
  ```
  The `?` on the decode (line 212) returns *before* `last_ts` is advanced (line 215). A single non-base64 message that is the first non-own, non-empty message in the history window re-fails on every `recv` poll until `timeout_ms` elapses. (Note: the line numbers shifted slightly from 07-08's `:200-223` to current `:200-226` because the cursor-advance block at 219-223 — which *does* advance on the no-message path — was already present. The bug is specifically the success-path `?` short-circuit at 212.)

### [MED] MED-NEW-T8 — extract_hex longest-run accepts arbitrary text as a frame → **STILL PRESENT**
- **位置:** `crates/transport/src/mcp.rs:156-181` + `:230-234`, `crates/transport/src/llm_api.rs:133-158` + `:207-215`
- **状态:** STILL PRESENT (both files' `extract_hex` logic is unchanged; mcp.rs diff did not touch `extract_hex`)
- **已核验:** both `McpTransport::extract_hex` and `LlmApiTransport::extract_hex` still scan for the longest contiguous `is_ascii_hexdigit()` run ≥ 8 chars and return it as the frame, with no length/tag/MAC check. `recv` hex-decodes whatever they return and hands it to the protocol layer.

### [MED] MED-NEW-T9 — Malleable send treats 4xx as success → **STILL PRESENT**
- **位置:** `crates/transport/src/malleable.rs:279-284`
- **状态:** STILL PRESENT (`malleable.rs` has zero diff)
- **已核验:** the only status check after `.send()` is `if resp.status().is_server_error() { return Err(Transient(...)); }` (line 279-283). A 401/403/404/410 falls through to `Ok(())` (line 284). Silent data loss on misconfigured profiles.

### [MED] MED-NEW-T10 — health_check ignores profile UA/headers → **STILL PRESENT**
- **位置:** `crates/transport/src/malleable.rs:333-348`
- **状态:** STILL PRESENT (`malleable.rs` has zero diff)
- **已核验:** `health_check` builds the request with `self.agent.get(&url).timeout(...).send()` (line 338-342) — it does not call `build_request`, so no profile `User-Agent`, no `Authorization`, no custom headers. The probe emits a bare reqwest identity while real beacons use the profile, producing two distinct HTTP fingerprints from one host.

### [LOW] LOW-NEW-T11 — SNI/ALPN parsed lossy → **STILL PRESENT**
- **位置:** `crates/transport/src/tls.rs:132` (SNI), `:149` (ALPN)
- **状态:** STILL PRESENT (`tls.rs` has zero diff)
- **已核验:** `String::from_utf8_lossy(&edata[5..5 + nl])` (SNI) and the analogous ALPN line unchanged.

### [LOW] LOW-NEW-T12 — sniff_client_hello swallows header-read error → **STILL PRESENT**
- **位置:** `crates/transport/src/tls.rs:350`
- **状态:** STILL PRESENT (`tls.rs` has zero diff)
- **已核验:** `let _ = read_exact(&mut r, &mut header);` unchanged; the `Result` is discarded.

### [LOW] LOW-NEW-T13 — LLM/MCP recv ignores timeout_ms → **STILL PRESENT**
- **位置:** `crates/transport/src/llm_api.rs:198` (`_timeout_ms`), `crates/transport/src/mcp.rs:216-249`
- **状态:** STILL PRESENT (both files' recv logic unchanged by the diffs)
- **已核验:** LLM `recv` still binds `_timeout_ms` and ignores it; MCP `recv` still checks `Instant::now() >= deadline` (line 245) only *after* a `rpc_call` (30 s per-call timeout at line 127) returns.

### [LOW] LOW-NEW-T14 — static conversation_id → correlation token → **STILL PRESENT**
- **位置:** `crates/transport/src/llm_api.rs:59` (`conversation_id: nanoid()`), `:190`
- **状态:** STILL PRESENT (`llm_api.rs` has zero diff)

### [LOW] LOW-NEW-T15 — MCP no HTTPS enforcement → **STILL PRESENT**
- **位置:** `crates/transport/src/mcp.rs:72` (`new` stores `server_url` verbatim)
- **状态:** STILL PRESENT (the api_key diff did not add a scheme check)

### [LOW] LOW-NEW-T16 — LLM with_api_url = SSRF / API-key-exfil sink → **STILL PRESENT**
- **位置:** `crates/transport/src/llm_api.rs:66-69`
- **状态:** STILL PRESENT (`llm_api.rs` has zero diff)

### [LOW] LOW-NEW-T17 — DoH extract_txt_data aborts whole scan on one malformed RR → **STILL PRESENT**
- **位置:** `crates/transport/src/doh_dns.rs:174-186`
- **状态:** STILL PRESENT (the DoH diff touched encoding, not `extract_txt_data`)
- **已核验:** `rr.get("type")?.as_u64()?` (line 177) still `?`-returns from the function on any malformed RR. Note `extract_txt_data` now receives URL-safe-no-pad data on the recv side (line 250), which is consistent with the new send encoding — good.

### [MED] MED-11 — TransportStack fallback no backoff/hysteresis → **STILL PRESENT**
- **位置:** `crates/transport/src/traits.rs:128-146`
- **状态:** STILL PRESENT (`traits.rs` zero diff)
- **已核验:** fallback loop at line 128-146 still only does `slot.fail_count += 1` (line 139) with no `thread::sleep`, no exponential backoff, no cooldown between attempts.

### [LOW] LOW-11 — static fake o365 JWT → **STILL PRESENT**
- **位置:** `crates/transport/src/malleable.rs:158`
- **状态:** STILL PRESENT (`malleable.rs` zero diff)
- **已核验:** the `Bearer eyJ0eXAiOiJKV1Q...fake-signature` literal is byte-identical. Still static, still contains `"iss":"https://sts.windows.net/fake-tenant"`, `"sub":"fake-user"`, `exp:1800000000`.

### [LOW] LOW-12 — DoH→Cloudflare, SMB→`\\.\pipe\nyx` defaults → **STILL PRESENT**
- **位置:** `crates/transport/src/doh_dns.rs:50`, `crates/transport/src/smb_pipe.rs:73`
- **状态:** STILL PRESENT (neither default touched by the diffs)

---

## Part 2 — Audit of the fix-in-progress code (new bugs in new code)

### [MED] NEW-MED-T18 — MCP `api_key` is `Option` with no default/enforcement; the auth fix is a no-op for any caller passing `None`
- **位置:** `crates/transport/src/mcp.rs:58` (field), `:72` (`new`), `:77` (`api_key` not seeded by default)
- **状态:** NEW (introduced by the 07-10 fix diff itself)
- **已核验:** the new constructor is `pub fn new(server_url, session_id, api_key: Option<String>)`. There is no `Default` impl, no `with_api_key` builder that forces a key, and no workspace caller to demonstrate intended usage. Every existing construction site (none in-tree) would have to be migrated to pass `Some(key)`; passing `None` reproduces the original HIGH-NEW-T4 vulnerability exactly.
- **影响:** the fix creates the *appearance* of authenticated MCP without making authentication the default. A future caller wiring this up has a 50/50 chance of shipping an unauthenticated channel, because nothing in the type system says "api_key required for production."
- **修复:** make the production constructor take `api_key: String` (non-optional); provide a separate `new_unauthenticated` gated behind `cfg(test)` or a `#[doc(hidden)]` for tests. Alternatively keep `Option` but `debug_assert!(api_key.is_some(), "MCP channel requires an api_key in production")` in `new`.

### [MED] NEW-MED-T19 — DoH `build_query_name` still has no total 253-byte name-length guard
- **位置:** `crates/transport/src/doh_dns.rs:114-129` (`build_query_name`), `:41` (`CHUNK_SIZE = 160`)
- **状态:** NEW (a latent issue that T1's fix did not address and that now matters more)
- **已核验:** `build_query_name` splits `b64_data` into ≤63-char labels and joins them as `{prefix}.{labels}.{domain}`. It **never checks the total constructed name length** against the RFC 1035 253-octet limit. The chunk size was sized assuming a "typical C2 domain (≤25 chars)" (line 40), but `new(domain, ...)` accepts any domain. Verified math: 160 raw bytes → 214 b64 chars → 4 labels (63+63+63+25) + prefix `c4294967295-255` (worst-case 15 chars for `u64::MAX` seq + chunk idx) + 5 dots + a 30-char domain = **~264 chars > 253**. A long domain or a high `send_seq` overflows.
- **影响:** with a sufficiently long C2 domain (e.g. a multi-level subdomain like `c2.long.attacker-domain.example.com`) or after enough sends that the sequence prefix grows, the DoH resolver rejects the name (FORMERR) and the chunk silently fails — reintroducing the "channel is dead for real traffic" symptom that T1 just fixed, but for a different reason.
- **修复:** in `build_query_name`, after constructing the name, `if name.len() > 253 { return Err(...) }` (or truncate the chunk and re-encode). Better: compute the max chunk size from `self.domain.len()` at `new()` time and set `CHUNK_SIZE` dynamically. Also clamp the prefix to a fixed-width format (e.g. `c{:08x}-{:02x}`, always 13 chars) so its length doesn't grow with `send_seq`.

### [MED] NEW-MED-T20 — SMB `read_exact` cannot distinguish "pipe broken" from "no data yet"; busy-spins until timeout on a closed pipe
- **位置:** `crates/transport/src/smb_pipe.rs:299-307`
- **状态:** NEW (residual after T2 fix; the overlapped fix removed the instant-failure symptom but exposed the underlying error-classification gap)
- **已核验:** now that the handle is synchronous, `ReadFile` returns 0 with `GetLastError() == ERROR_BROKEN_PIPE` (109) or `ERROR_PIPE_NOT_CONNECTED` (229) when the peer closes the pipe. The code:
  ```rust
  if result == 0 || bytes_read == 0 {
      if start.elapsed().as_millis() as u32 >= timeout_ms {
          return false;
      }
      std::thread::sleep(std::time::Duration::from_millis(10));
      continue;
  }
  ```
  treats *every* `result == 0` as "no data yet" and sleeps+retries. On a broken pipe this loops for the full `timeout_ms` (caller's recv budget), burning ~`timeout_ms/10ms` iterations and a 10 ms-granularity wakeups, then returns `false` → `recv` reports `Transient`/`Timeout` instead of `Dead`. A legitimate "server gone" is indistinguishable from "server slow," so the `TransportStack` never marks the SMB slot dead via this path and keeps retrying it.
- **Note on synchronous semantics:** on a *blocking* pipe handle with no data but still connected, `ReadFile` **blocks** (does not return 0) until data arrives or the pipe closes — so the `bytes_read == 0` retry branch is only reached on actual error/EOF, never on "waiting for data." The 10 ms sleep is therefore useless for its stated purpose and only ever masks real failures.
- **影响:** on pipe disconnect, `recv` consumes the full timeout budget and reports the wrong error class; the channel is never auto-dead-marked via recv failure. Latency/DOS on the receive path.
- **修复:** on `result == 0`, call `GetLastError()`; map `ERROR_BROKEN_PIPE`/`ERROR_PIPE_NOT_CONNECTED`/`ERROR_NO_DATA` to an immediate `false` (and have `recv` translate that to `Dead`, not `Transient`/`Timeout`). Reserve the retry-on-timeout path for genuinely blocking reads. (Also: the dead `let err = unsafe { GetLastError() };` bindings at line 232 and 250, flagged in 07-08, are still present and still unused — `err` is bound then never read at line 232, and read only in the `ERROR_PIPE_BUSY` branch at 250-253 but not in the final `Dead` return.)

### [LOW] NEW-LOW-T21 — DoH module doc has stale base64-expansion invariant ("~216" vs actual 214)
- **位置:** `crates/transport/src/doh_dns.rs:10` (doc), `:38-40` (constant comment)
- **状态:** NEW (introduced/mismatched by the T1 fix — the doc was updated to mention URL-safe but the char-count claim was not corrected)
- **已核验:** line 38-40 still says *"160 raw bytes → ~216 base64 chars"*. With `URL_SAFE_NO_PAD`, 160 bytes encode to **214** chars (verified by direct computation). The doc invariant used to justify the chunk size is off-by-2. Harmless today (214 < 216, so the margin still holds), but a future maintainer trusting "216" could pick a chunk size that overflows.
- **修复:** correct the comment to 214, or better, derive `CHUNK_SIZE` from a `max_raw_bytes_for_domain(domain_len)` helper so the invariant is encoded, not prose.

### [LOW] NEW-LOW-T22 — MCP `rpc_call` builder-chain break relies on ureq's `Request` being `Send`+ reusable; no test exercises the auth header on the wire
- **位置:** `crates/transport/src/mcp.rs:120-138`
- **状态:** NEW (introduced by the T4 fix)
- **已核验:** the fix breaks the previously-chained `self.agent.post(...).set(...).timeout(...).send_json(body)` into a `let mut req = ...; if let Some(auth) = ... { req = req.set(...); }; req.send_json(body)`. The comment (line 120-122) correctly notes ureq's `set`/`timeout`/`send_json` take `mut self -> Self`. The two new tests (`auth_header_*`) only test `auth_header()` in isolation — **no test** verifies that `rpc_call` actually attaches the header to the outgoing request (which would require a mock server). The header contract is asserted at the helper level but not at the integration level.
- **影响:** low — if a future ureq refactor changed `set` to consume-and-not-return, the header would silently vanish and only `auth_header()` tests would still pass. The fix is correct against current ureq; this is a test-coverage gap, not a live bug.
- **修复:** add a `mockito`-style test that stands up a local HTTP server, points `McpTransport` at it with `Some(api_key)`, calls `rpc_call`, and asserts the received `Authorization` header. Or assert via `req.header("Authorization")` introspection if ureq exposes it.

---

## Part 3 — Fresh-eyes findings (missed by 07-08)

### [MED] NEW-MED-T23 — LLM `recv` enforces a 15-second send-side rate limit *before* the single downlink call, blowing the recv timeout budget
- **位置:** `crates/transport/src/llm_api.rs:198-204`
- **状态:** NEW
- **已核验:** `recv` begins with `self.enforce_rate_limit();` (line 199). `enforce_rate_limit` (line 161-170) sleeps until `FREE_TIER_RATE_LIMIT_MS` (15 000 ms) has elapsed since the *last send*. The same `last_send` timestamp is updated by both `send` (line 181, via `enforce_rate_limit`) and `recv` (line 199, via `enforce_rate_limit`) — they share one throttle. So if the implant just sent a frame, the *next* `recv` call (even with `timeout_ms = 1000`) sleeps 15 s before it even issues the downlink POST. Then the POST itself has a 60 s timeout (line 99). `_timeout_ms` (line 198) is ignored throughout.
- **影响:** the LLM channel's recv path can block for 15 s + 60 s = 75 s regardless of the caller's requested timeout, and the send/recv throttle is coupled so a burst of sends starves recv. Combined with T13 (recv ignores timeout_ms), the `TransportStack` caller's deadline contract is unenforceable for this channel.
- **修复:** (a) decouple send and recv throttles (separate `last_send`/`last_recv` timestamps, or a single `last_request` with a smaller floor for recv); (b) honor `timeout_ms` by bounding the `post_message` `.timeout(...)` and short-circuiting if the budget is already exhausted.

### [MED] NEW-MED-T24 — MCP `recv` swallows a server-returned `error` JSON-RPC object as "no data" and keeps polling, masking real failures
- **位置:** `crates/transport/src/mcp.rs:144-147` (rpc_call error mapping), `:216-249` (recv loop)
- **状态:** NEW
- **已核验:** `rpc_call` returns `Err(TransportError::Transient("MCP RPC error"))` whenever `json.get("error").is_some()` (line 145-147). In `recv`'s poll loop (line 227-243), the match arm `Err(TransportError::Timeout) => {}` swallows timeouts, but a `Transient` from a JSON-RPC error hits `Err(e) => return Err(e)` (line 242) — so a server that returns `{"error":{"code":...}}` on every poll will make `recv` return `Transient` immediately, and the outer `TransportStack` increments `fail_count`. That's arguably correct. **But** consider the case where the server flaps between `error` and empty-success: each empty success resets nothing, each error returns early. The subtler issue is at line 145: **any** JSON-RPC error — including a recoverable `"method not found"` or a transient server-side `internal error` — is collapsed into one generic `Transient` string with no code/status surfaced. The operator cannot distinguish "server doesn't know `get_suggestions`" (a Dead misconfiguration) from "server briefly 500'd" (a Transient blip).
- **影响:** a misconfigured MCP server (wrong tool name) makes `recv` return `Transient` forever rather than `Dead`, so the `TransportStack` retries indefinitely (up to `max_consecutive_fails`) instead of failing fast. Forensically noisy (repeated failed POSTs) and operationally confusing.
- **修复:** inspect the JSON-RPC `error.code`; map `-32601` (method not found) and similar permanent errors to `Dead`, and surface the code in the error string for diagnostics.

### [LOW] NEW-LOW-T25 — MCP `notification_body` / `health_check` sends an `initialize` *notification* (no `id`), but MCP `initialize` is a *request* requiring a response
- **位置:** `crates/transport/src/mcp.rs:99-105` (`notification_body` omits `id`), `:252-270` (`health_check` uses it for `initialize`)
- **状态:** NEW
- **已核验:** `notification_body` (line 99-105) builds `{"jsonrpc":"2.0","method":name,"params":params}` with **no `id` field**, making it a JSON-RPC *notification* (server must not reply, per JSON-RPC 2.0 §4). `health_check` (line 254-264) calls `notification_body("initialize", ...)` to probe liveness. But the MCP spec (`initialize`) is a *request*: the server is expected to respond with its capabilities. A spec-compliant MCP server receiving a notification-form `initialize` may legitimately ignore it (no reply), causing `rpc_call` to time out on `.into_json()` (no body) → `health_check` returns `None` → a **healthy** server is reported dead.
- **影响:** the health probe is malformed against a strict MCP server; `init()`/`probe_health()` could mark a live channel dead, suppressing fallback-to-MCP. (Lenient servers that reply anyway mask this.) Low because it only affects the probe path, not send/recv.
- **修复:** use `tool_call_body`/a request-form body (with `id`) for `initialize`, or send a real `initialize` request. Reserve `notification_body` for genuine notifications (`notifications/initialized`).

### [LOW] NEW-LOW-T26 — `TransportStack::recv` never falls back: if the active channel's recv errors, the whole stack returns the error
- **位置:** `crates/transport/src/traits.rs:152-158`
- **状态:** NEW (architectural asymmetry; the 07-08 audit focused on `send` fallback, not recv)
- **已核验:**
  ```rust
  pub fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
      if self.active < self.channels.len() {
          self.channels[self.active].transport.recv(timeout_ms)
      } else {
          Err(TransportError::Dead("no active channel"))
      }
  }
  ```
  Unlike `send` (line 105-149), which has a full priority-ordered fallback loop, `recv` only ever reads from `self.active`. If the active channel's `recv` returns `Transient`/`Timeout`/`Dead`, the stack propagates it directly — no attempt to recv from a healthy alternate channel. The `active` index is only re-pointed by `probe_health` (line 160-184) or a successful `send` fallback (line 133).
- **影响:** if the active channel is a recv-side failure (e.g. Slack poison message T7, LLM stateless recv T5) but a *send* on it would succeed (so `active` isn't rotated away by `send`'s fallback), the implant cannot receive tasking even though a healthy alternate channel exists. The multi-channel promise is asymmetric: resilient send, fragile recv.
- **修复:** add a fallback loop in `recv` mirroring `send`'s — on `Err` from `self.active`, iterate healthy lower-priority channels and try their `recv`. Mind the `timeout_ms` budget across attempts.

### [LOW] NEW-LOW-T27 — Slack `poll_history` uses `limit=5` and `oldest=last_ts` but Slack `conversations.history` returns *newest first*; the cursor-advance can skip frames under interleaving
- **位置:** `crates/transport/src/slack_api.rs:187-223`
- **状态:** NEW
- **已核验:** `poll_history` requests `conversations.history` with `limit=5` and `oldest=<last_ts>` (line 187-192). Slack returns messages newest-first. The loop (line 200) iterates and returns the **first** non-own, non-empty message (line 216), advancing `last_ts` to that message's `ts` (line 215). Consider three queued C2 frames with timestamps t1 < t2 < t3, all newer than `last_ts`. The API returns `[t3, t2, t1]`. The loop picks `t3` (first non-own), sets `last_ts = t3`, returns t3's frame. Next poll, `oldest = t3`, so `t1` and `t2` — which are *older* than `t3` — are now **excluded by the `oldest` filter** and are never delivered.
- **影响:** whenever the C2 server posts multiple frames faster than the implant polls (1.2 s cooldown on send, 500 ms poll), frames between the newest and the previous-newest are silently dropped. Order is also inverted (newest delivered first). A subtle data-loss race on the inbound path.
- **修复:** either process *all* non-own messages in the returned window in chronological order (reverse the slice, deliver each, set `last_ts` to the newest), or use Slack's `cursor`-based pagination (`has_more` + `response_metadata.next_cursor`) instead of `oldest`. At minimum, advance `last_ts` to the **oldest** message consumed, not the first one found, and drain the whole window.

### [LOW] NEW-LOW-T28 — `nanoid()` in `llm_api.rs` uses `String::from_utf8(chars).unwrap_or_default()`, silently producing an empty conversation_id on a (impossible-but-defended) non-UTF8 byte
- **位置:** `crates/transport/src/llm_api.rs:252-265`
- **状态:** NEW
- **已核验:** the hand-rolled nanoid maps `0..=25 → b'a'+idx`, etc., all ASCII, so `from_utf8` cannot fail in practice. But the `.unwrap_or_default()` turns any future regression (e.g. someone changes the charset to include high bytes) into an *empty* `conversation_id` with no panic — every prompt would then be prefixed with `[] analyze debug log:` instead of `[xxxxxxxxxxxx]...`, collapsing all implants' prompts to one shared prefix and worsening T14 (correlation). Defensive code that masks a bug rather than failing loudly.
- **修复:** `.expect("nanoid charset is ASCII")` — the charset is statically ASCII, so a failure is a logic bug and should panic, not degrade silently. (Better: use the `nanoid` crate like the field name implies, instead of a hand-rolled RNG.)

### [LOW] NEW-LOW-T29 — DoH `send` rate-limit `last_send` is updated *after* the inter-chunk sleep, not after each query, skewing the 1 QPS cadence
- **位置:** `crates/transport/src/doh_dns.rs:204-221`
- **状态:** NEW
- **已核验:** the send loop:
  ```rust
  for (i, chunk) in raw_chunks.iter().enumerate() {
      self.enforce_rate_limit();          // sleeps if <1s since last_send
      let chunk_b64 = ...;
      ... self.doh_query(&qname, ...)?;   // the actual query (variable latency)
      if i + 1 < raw_chunks.len() {
          thread::sleep(Duration::from_millis(QUERY_INTERVAL_MS));  // 1s hard sleep
      }
      self.last_send = Some(Instant::now());  // recorded after the sleep
  }
  ```
  Two issues: (a) there are **two** rate-limit mechanisms — `enforce_rate_limit` (line 204) *and* an unconditional 1 s sleep (line 217) — so between chunks the implant actually waits `time_since_last_send + 1s` (the enforce then sleeps a full extra second); (b) `last_send` is stamped at line 220 *after* the inter-chunk sleep, so on the *next* iteration `enforce_rate_limit` measures from the post-sleep stamp and effectively never throttles (it always sees ≥1 s elapsed). The net cadence is "1 s sleep per chunk" driven solely by line 217, with `enforce_rate_limit` as dead weight on the intra-frame path.
- **影响:** low — the cadence is still ~1 QPS (the hard sleep enforces it), but the rate-limit machinery is redundant and misleading, and the *first* chunk of a multi-chunk frame may fire immediately after a previous frame's last chunk (no gap between frames), producing a 2-query burst at frame boundaries that a DNS-rate anomaly detector could flag.
- **修复:** pick one mechanism. Stamp `last_send` immediately after each `doh_query` (before the optional sleep), drop the unconditional `thread::sleep` at line 217, and let `enforce_rate_limit` own the cadence uniformly across chunks and frames.

### [LOW] NEW-LOW-T30 — `MalleableTransport::build_request` advances `uri_idx` and `ua_idx` together, but `health_check`/`recv` call sites desynchronise them from `send`
- **位置:** `crates/transport/src/malleable.rs:200-211` (rotation), `:265`/`:292` (`send`/`recv` call `next_uri`), `:234` (`build_request` calls `next_ua`)
- **状态:** NEW
- **已核验:** `next_uri` and `next_ua` each advance their own counter independently. `send` calls `next_uri()` (line 265) then `build_request` (line 268) which calls `next_ua()` (line 234) — so one send consumes one URI *and* one UA. But `recv` (line 292) calls `build_request` (which consumes a UA) on every poll iteration (every 500 ms), rapidly burning through the UA pool while the URI pool advances in lockstep — so the (URI, UA) pairing drifts from the deterministic round-robin an operator might expect for cover consistency. `health_check` (line 333-348) reads `uris.first()` directly without rotating, so it doesn't consume either counter. The net effect: the *observed* UA sequence on the wire depends on how many recv polls happened between sends, which is timing-dependent — undermining the "deterministic profile rotation" the module advertises.
- **影响:** low (cover-quality, not correctness) — an analyst sees an inconsistent (URI, UA) combination matrix that doesn't match any single browser's real traffic pattern, which is itself a mild fingerprint. Hard to exploit, easy to detect by a defender correlating requests.
- **修复:** either rotate URI and UA from a single coupled index (one counter, `(uris[i], uas[i % uas.len()])`), or document that the pairing is non-deterministic. Reserve `health_check`'s no-rotation read as intentional.

---

## 已验证干净的区域 (INFO — checked and sound)

- **TLS-weakening sweep clean (re-verified).** `grep` for `danger_accept_invalid|insecure|accept_invalid|verify_mode|min_tls_version|dangerous` over `crates/transport` returns **zero** matches. All HTTPS channels (slack/llm/doh/mcp/malleable) use default ureq/reqwest rustls with cert validation on. No cert pinning is configured (coverage gap, not a weakness). No new TLS-weakening code introduced by the 07-10 diffs.
- **DoH T1 fix is correct at the encoding layer.** `URL_SAFE_NO_PAD`'s alphabet (`A-Za-z0-9-_`) is DNS-label-safe for all 256 byte values (verified by the new `url_safe_base64_emits_only_dns_label_chars` test covering `0x00..=0xFF` and by direct computation: `0xFF → "_w"`, `0xFB → "-w"`, no `+`/`/`/`=`). Send and recv use the same engine (line 206 / 250), so the round-trip is consistent. The two new tests are genuine (they would have failed under the old `STANDARD` engine).
- **SMB T2 fix addresses the root cause.** Removing `FILE_FLAG_OVERLAPPED` (constant deleted at line 29, `CreateFileW` arg changed to `0` at line 244) makes the synchronous `ReadFile`/`WriteFile` calls with `lpOverlapped = NULL` (line 273, 295) *correct* per MSDN. The fix took the simpler of the two 07-08-recommended options (drop overlapped, keep blocking), which matches the existing `thread::sleep` retry logic. The length-prefix framing cap (`recv` checks `payload_len > self.max_frame_size()` at line 170 before allocating) is still sound — no unbounded allocation from a peer-supplied length.
- **No TLS-cert-weakening or new `unsafe` introduced.** The SMB diff's only `unsafe` change is the `CreateFileW` argument list (flag value), not a new unsafe block. The FFI signatures (line 32-67) are unchanged. The `Drop` impl (line 331-335) correctly closes the handle.
- **MCP T4 partial fix's header logic is correct against current ureq.** Breaking the builder chain (`let mut req = ...; if let Some(auth) = ... { req = req.set("Authorization", &auth); }; req.send_json(body)`) is valid because ureq's `Request::set`/`timeout`/`send_json` take `mut self -> Self`. The header is attached before `send_json` fires. The two new tests correctly assert the `auth_header()` contract (None without key, `Bearer <key>` with key).
- **`h2.rs` HTTP/2 frame parser remains bounds-safe** (unchanged; re-confirmed per 07-08). `from_frames` validates every payload via `raw.get(p+9..p+9+len).ok_or(...)?` and loops on `while p + 9 <= raw.len()`. No panics, no unchecked indexing.
- **`tls.rs::parse_client_hello` bounds discipline unchanged** (re-confirmed). Every variable-length field (session id, cipher list, compression, extensions, ec_point_formats, supported_versions) is bounds-checked before slicing. JA3/JA4 computation is pure functional hashing with correct GREASE filtering. `sniff_client_hello` enforces the 16384-byte record cap (line 356-361). The only (low) issues are T11 (lossy SNI/ALPN) and T12 (swallowed header read), both pre-existing.
- **No new hardcoded secrets in the diffs.** The 07-10 changes introduce no new credential literals. The existing fake test values (`xoxb-test`, `sk-test`) remain test-only. The o365 fake JWT (LOW-11) is unchanged.
- **Error classification does not leak credentials (re-confirmed).** `mcp.rs:132-138` collapses ureq errors to generic `Transient`/`Timeout` strings (the `Authorization` header is not part of ureq's error `Display`). `slack_api.rs:133-152`, `llm_api.rs:101-107` likewise. The new MCP `Authorization` header value is never logged or included in an error string.
- **No CRLF/header-injection sink reaches the wire (re-confirmed).** `mcp.rs:129` uses ureq's typed `Request::set(name, val)` which validates header names/values at construction. No `format!` interpolates implant-controlled bytes into a header or URL.
- **Length checks before allocation are uniformly present.** `doh_dns.rs:193`, `llm_api.rs:177`, `mcp.rs:198`, `smb_pipe.rs:130`, `malleable.rs:254`, `slack_api.rs:241` all reject `frame.len() > max_frame_size()` with `PayloadTooLarge` before any encoding/allocation. SMB additionally re-checks the peer-supplied length prefix (line 170).
- **`webtransport.rs` is still an honest, documented stub** — every method returns `Dead`/`None`, `init()` returns `Dead`, tests assert stub behaviour. The caveat (a registered stub permanently occupies a fallback slot that can never succeed) stands but is unchanged.

---

## Severity roll-up (07-10)

| ID | Sev | File:line | One-liner | 状态 vs 07-08 |
|----|-----|-----------|-----------|---------------|
| HIGH-NEW-T1 | — | doh_dns.rs:29 | base64 `+`/`/` as DNS labels | **FIXED** |
| HIGH-NEW-T2 | — | smb_pipe.rs:244 | overlapped handle used sync | **FIXED** (residual → NEW-MED-T20) |
| HIGH-NEW-T3 | HIGH | emitter.rs + all ctors | FingerprintEmitter dead code; default JA3 on all HTTPS | **PARTIALLY FIXED** (documented, not wired) |
| HIGH-NEW-T4 | HIGH | mcp.rs:58,72,128 | MCP auth is optional `Option`; `None` reproduces original vuln | **PARTIALLY FIXED** (see NEW-MED-T18) |
| MED-NEW-T5 | MED | llm_api.rs:83,198,74 | LLM recv broken (stateless) + XOR leaks | **STILL PRESENT** |
| MED-NEW-T6 | MED | traits.rs:96-102 | init_all never sets healthy | **STILL PRESENT** |
| MED-NEW-T7 | MED | slack_api.rs:210-216 | poison message blocks recv | **STILL PRESENT** |
| MED-NEW-T8 | MED | mcp.rs:156, llm_api.rs:133 | extract_hex accepts arbitrary text | **STILL PRESENT** |
| MED-NEW-T9 | MED | malleable.rs:279-284 | send treats 4xx as success | **STILL PRESENT** |
| MED-NEW-T10 | MED | malleable.rs:333-348 | health_check ignores profile UA/headers | **STILL PRESENT** |
| LOW-NEW-T11 | LOW | tls.rs:132,149 | SNI/ALPN parsed lossy | **STILL PRESENT** |
| LOW-NEW-T12 | LOW | tls.rs:350 | sniff swallows header-read error | **STILL PRESENT** |
| LOW-NEW-T13 | LOW | llm_api.rs:198, mcp.rs:216 | recv ignores timeout_ms | **STILL PRESENT** |
| LOW-NEW-T14 | LOW | llm_api.rs:59,190 | static conversation_id | **STILL PRESENT** |
| LOW-NEW-T15 | LOW | mcp.rs:72 | no HTTPS enforcement on MCP URL | **STILL PRESENT** |
| LOW-NEW-T16 | LOW | llm_api.rs:66-69 | with_api_url SSRF sink | **STILL PRESENT** |
| LOW-NEW-T17 | LOW | doh_dns.rs:174-186 | one malformed RR aborts TXT scan | **STILL PRESENT** |
| MED-11 | MED | traits.rs:128-146 | fallback no backoff | **STILL PRESENT** |
| LOW-11 | LOW | malleable.rs:158 | static fake o365 JWT | **STILL PRESENT** |
| LOW-12 | LOW | doh_dns.rs:50, smb_pipe.rs:73 | Cloudflare/`nyx` defaults | **STILL PRESENT** |
| **NEW-MED-T18** | **MED** | mcp.rs:58,72 | api_key is `Option` w/o enforcement — auth fix is a no-op for `None` | NEW (in fix diff) |
| **NEW-MED-T19** | **MED** | doh_dns.rs:114-129 | `build_query_name` no 253-byte total-length guard | NEW |
| **NEW-MED-T20** | **MED** | smb_pipe.rs:299-307 | read_exact can't distinguish broken pipe from no-data; busy-spins to timeout | NEW (residual post-T2) |
| **NEW-MED-T23** | **MED** | llm_api.rs:198-204 | recv enforces 15 s send-throttle before the downlink call | NEW |
| **NEW-MED-T24** | **MED** | mcp.rs:144-147,216-249 | recv collapses all JSON-RPC errors to generic Transient; misconfig never Dead | NEW |
| NEW-LOW-T21 | LOW | doh_dns.rs:10,38-40 | stale "~216 chars" doc (actual 214) | NEW |
| NEW-LOW-T22 | LOW | mcp.rs:120-138 | auth header not tested on the wire (no integration test) | NEW |
| NEW-LOW-T25 | LOW | mcp.rs:99-105,252-270 | health_check sends `initialize` as a notification (no `id`) | NEW |
| NEW-LOW-T26 | LOW | traits.rs:152-158 | `recv` has no fallback (unlike `send`) | NEW |
| NEW-LOW-T27 | LOW | slack_api.rs:187-223 | `oldest=last_ts` + newest-first ordering drops interleaved frames | NEW |
| NEW-LOW-T28 | LOW | llm_api.rs:252-265 | `nanoid` `unwrap_or_default` masks a bug as empty id | NEW |
| NEW-LOW-T29 | LOW | doh_dns.rs:204-221 | dual rate-limit; `last_send` stamped post-sleep skews cadence | NEW |
| NEW-LOW-T30 | LOW | malleable.rs:200-211 | URI/UA counters desynchronise across send/recv/health | NEW |

---

## Summary & top recommendations

**Net change vs 07-08:** 2 of 22 prior findings are **FIXED** (T1, T2 — both root-cause), 2 are **PARTIALLY FIXED** (T3 documented-only, T4 optional-and-unwired), and **18 are byte-for-byte STILL PRESENT**. The fix pass concentrated on the two "channel is non-functional" HIGHs and the two "documented honesty" items; it did **not** touch the trait layer (T6/MED-11), the Slack poison bug (T7), anything in the LLM channel (T5/T8/T13/T14/T16), or the malleable status/health bugs (T9/T10/LOW-11).

**New bugs introduced by the fixes (3 MED, 2 LOW):**
- NEW-MED-T18 — the MCP auth fix ships as `Option<String>` with no default/enforcement, so it is silently inert for any `None` caller. This is the most important new issue: a "fixed" HIGH that is still exploitable in its default configuration.
- NEW-MED-T19 — the DoH fix corrected the alphabet but left the total-name-length guard absent; a long domain or high sequence number reintroduces "channel dead for real traffic" by a different mechanism.
- NEW-MED-T20 — the SMB fix removed the instant-failure mode but exposed the `read_exact` error-classification gap (broken pipe now busy-spins to timeout instead of failing fast).

**Top-5 to fix next:**
1. **HIGH-NEW-T4 / NEW-MED-T18** — make MCP `api_key` a required `String` (or enforce non-`None` in production `new`). The current state is a HIGH vulnerability wearing a fix's clothes.
2. **MED-NEW-T6 + MED-11** (`traits.rs`) — `init_all` must set `healthy=true` on Ok, and the fallback loop needs backoff. Untouched since 07-08; the multi-channel fallback's core value is silently degraded.
3. **MED-NEW-T7 + NEW-LOW-T27** (`slack_api.rs`) — the inbound path has two data-loss bugs (poison-message stall + oldest-cursor frame skipping). Both are single-line fixes.
4. **MED-NEW-T5 + NEW-MED-T23** (`llm_api.rs`) — the LLM channel is functionally non-recieving (stateless API) *and* its recv path blocks 75 s ignoring the timeout. Either implement properly (conversation history / server-side store) or mark the channel send-only.
5. **HIGH-NEW-T3** — at minimum, ensure the operator-facing README/profile docs (not just source comments) front-load "outbound JA3 is NOT controllable today," so the documentation fix actually reaches the operator, not just the code reviewer.
