# Nyx Transport Crate — Line-by-Line Security Audit (2026-07-08)

**Scope:** `crates/transport/src/` (lib.rs, traits.rs, h2.rs, tls.rs, doh_dns.rs, slack_api.rs, llm_api.rs, mcp.rs, webtransport.rs, smb_pipe.rs, malleable.rs, emitter.rs) + `crates/transport/tests/fingerprint.rs`.
**Method:** static review, exact line citations from observed code. No formatters/linters/test-suites run.

---

## Baseline re-verification

### MED-11 — TransportStack fallback no backoff/hysteresis → **CONFIRMED**
- **位置:** `crates/transport/src/traits.rs:127-146`
- **已核验:** the fallback loop iterates `self.channels.iter_mut().enumerate()` and on `TransportError::Transient` only does `slot.fail_count += 1` (line 138-140). There is **no `thread::sleep`, no exponential backoff, no cooldown** between attempts. A caller hammering `send()` in a retry loop will spin through every channel on every call.
- **状态:** bug persists unchanged at the cited lines.

### LOW-11 — o365 fake JWT → **CONFIRMED**
- **位置:** `crates/transport/src/malleable.rs:158`
- **已核验:** `("Authorization".into(), "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mYWtlLXRlbmFudCIsImlhdCI6MTcwMDAwMDAwMCwibmJmIjoxNzAwMDAwMDAwLCJleHAiOjE4MDAwMDAwMDAsInN1YiI6ImZha2UtdXNlciJ9.fake-signature".into())`. Static, hardcoded, identical across every beacon. Payload literally contains `"iss":"https://sts.windows.net/fake-tenant"`, `"sub":"fake-user"`, `exp:1800000000`.
- **状态:** persists. See NEW-LOW-T8 for the expanded IOC analysis.

### LOW-12 — DoH default Cloudflare + SMB default pipe name → **CONFIRMED (both halves)**
- **DoH:** `crates/transport/src/doh_dns.rs:50` `const DEFAULT_DOH_SERVER: &str = "https://cloudflare-dns.com/dns-query";`, used as the `unwrap_or_else` default in `new()` at `:88-90`.
- **SMB:** `crates/transport/src/smb_pipe.rs:74` `const DEFAULT_PIPE: &str = "\\\\.\\pipe\\nyx";`, used by `new()` (`:105-107`) and `Default` (`:120-124`).
- **状态:** both persist.

---

## NEW findings

### [HIGH] NEW-HIGH-T1 — DoH tunnel uses base64 (`+`/`/`) directly as DNS labels; channel is broken for real binary traffic
- **位置:** `crates/transport/src/doh_dns.rs:114-130` (`build_query_name`), `:206` (`BASE64.encode(chunk)`)
- **已核验:**
  - `send()` base64-encodes each raw chunk with the **STANDARD** alphabet (`use base64::engine::general_purpose::STANDARD as BASE64`, line 29; `let chunk_b64 = BASE64.encode(chunk)`, line 206) then passes it to `build_query_name`.
  - `build_query_name` splits that string into ≤63-char labels and joins them as subdomains (`labels.push(&remaining[..split])`, line 125; `format!("{}.{}.{}", prefix, labels.join("."), self.domain)`, line 129). **No character sanitization.**
  - Standard base64 emits `+` (value 62) and `/` (value 63). RFC 1035 §2.3.4 restricts DNS label chars to letters/digits/hyphen. A `/` or `+` makes the name malformed.
  - The unit tests at `:312-355` only ever feed `"A".repeat(200)`, `vec![0xAA; 160]`, and `vec![0xFF; CHUNK_SIZE]`. `0xAA` base64-encodes to all-`q` (valid); `0xFF` base64-encodes to `/` — but the test only asserts `qname.len() <= 253`, never that the labels are RFC-legal, so it passes on an invalid name.
- **描述:** for random/encrypted C2 bytes, ~1/32 of base64 chars are `+`/`/`; a 160-byte chunk yields ~216 chars, so **nearly every chunk contains invalid label characters**. The DoH resolver will return FORMERR/SERVFAIL, the send loop returns `Transient`, `fail_count` climbs, and the channel is marked dead.
- **影响:** the DoH covert channel — advertised as a primary fallback for restricted-egress environments — does not actually exfiltrate real (encrypted, binary) C2 frames. It only "works" against the synthetic all-`A`/all-`0xAA` test payloads.
- **修复:** use URL-safe base64 **and** a DNS-label-safe alphabet (or base32). Real-world DNS-tunnel tooling (iodine, dnscat2) uses base32/base64url exactly for this reason. Also reject (or re-chunk) when the final name would exceed 253 bytes — `build_query_name` never checks the total length.

### [HIGH] NEW-HIGH-T2 — SMB pipe handle opened `FILE_FLAG_OVERLAPPED` but read/written synchronously (NULL OVERLAPPED) → busy-loop, channel non-functional
- **位置:** `crates/transport/src/smb_pipe.rs:245` (open flag), `:264-278` (`write_all`), `:282-314` (`read_exact`)
- **已核验:**
  - `connect_inner` opens the pipe with `FILE_FLAG_OVERLAPPED` (line 245).
  - `write_all` calls `WriteFile(self.handle, ..., std::ptr::null())` — `lpOverlapped = NULL` (line 274).
  - `read_exact` calls `ReadFile(self.handle, ..., std::ptr::null())` — `lpOverlapped = NULL` (line 296).
  - MSDN requires that a handle opened with `FILE_FLAG_OVERLAPPED` **must** be passed a valid `OVERLAPPED*`; passing NULL is undefined and on modern Windows `ReadFile`/`WriteFile` fail immediately with `ERROR_INVALID_PARAMETER` (return 0).
  - `read_exact` then enters: `if result == 0 || bytes_read == 0 { ... std::thread::sleep(10ms); continue; }` (line 300-307) — it spins retrying a permanently-failing call until `timeout_ms` elapses, burning a core.
- **描述:** the overlapped/synchronous modes are mixed. Every `ReadFile`/`WriteFile` errors instantly; `read_exact` treats the instant failure as "no data yet" and busy-loops; `write_all` returns `false`, so `send` returns `Transient` and disconnects.
- **影响:** the SMB lateral-movement channel cannot send or receive any frame; `recv` busy-loops until timeout. On Windows the channel is effectively the same as the non-Windows dead stub, but worse because it consumes CPU.
- **修复:** pick one mode. Either drop `FILE_FLAG_OVERLAPPED` from `CreateFileW` (simplest — blocking I/O matches the `thread::sleep` retry logic), or implement true overlapped I/O with a real `OVERLAPPED` + `GetOverlappedResult`/`CancelIo`. Also bind `let err = unsafe { GetLastError() };` at line 234 and 251 — currently dead bindings (`:234` is entirely unused).

### [HIGH] NEW-HIGH-T3 — `FingerprintEmitter` is dead code; every HTTPS transport emits a default (non-browser) JA3/JA4 — the crate's own #1 detection vector
- **位置:** `crates/transport/src/lib.rs:1-30` (stated goal), `crates/transport/src/emitter.rs:43-93` (trait + `best()`), all transport constructors
- **已核验:**
  - `lib.rs:3-5`: *"The #1 way modern C2 traffic is caught at the edge is fingerprinting the transport, not the HTTP layer: TLS [JA3]/[JA4] over the ClientHello."*
  - `emitter.rs` defines `FingerprintEmitter`, `DefaultEmitter`, `RquestEmitter`, and `best()` — a whole abstraction for producing browser-matching ClientHellos.
  - Workspace grep for `FingerprintEmitter|emitter::best|Profile::Chrome|Profile::Firefox` returns matches **only inside `emitter.rs` (definition + tests) and `lib.rs` (module decl + doc)**. No transport channel references it.
  - Every HTTPS-based channel builds its client with the default builder and no JA3 control: `slack_api.rs:82-84` `ureq::AgentBuilder::new()`, `llm_api.rs:58` `Agent::new()`, `doh_dns.rs:92` `Agent::new()`, `mcp.rs:69` `Agent::new()`, `malleable.rs:98-101` `reqwest::blocking::Client::builder()`.
- **描述:** the emitter abstraction exists but is unwired. Default rustls/ureq/reqwest ClientHellos are a well-known, stable, non-browser JA3 (`tls/...` extension order, no GREASE, fixed cipher order) that every modern NGFW fingerprints.
- **影响:** despite shipping a JA3/JA4 *parser* and an *emitter seam*, all outbound C2 HTTPS traffic is trivially fingerprintable as "rustls client," which is the exact failure mode this crate's documentation says it exists to prevent. Operators relying on the malleable/slack/llm/doh/mcp profiles for blending are not actually blending at the TLS layer.
- **修复:** thread the emitter into each transport's client construction (accept a `&dyn FingerprintEmitter` in each `new()`, or have the `TransportStack` own one and inject it). At minimum, document that JA3 impersonation is unimplemented until `wreq`/`rquest` lands, so operators do not assume cover.

### [HIGH] NEW-HIGH-T4 — MCP channel is unauthenticated; `session_id` is the only "credential" and is sent in cleartext JSON → frame injection / tasking theft
- **位置:** `crates/transport/src/mcp.rs:52-57` (struct, no token field), `:182-188` and `:198-203` (`session_id` in `arguments`), `:100-128` (`rpc_call` sets no auth header)
- **已核验:**
  - `McpTransport` has fields `server_url, session_id, agent, request_id` — **no API key, no bearer token, no HMAC**.
  - `send` puts `session_id` in `arguments` (line 186); `recv` puts `session_id` in `arguments` (line 201). `rpc_call` only sets `Content-Type` (line 107).
  - Anyone who learns or guesses a `session_id` can POST `tools/call submit_telemetry` with that session → inject arbitrary C2 frames (impersonate the implant, poison results); or POST `get_suggestions` → steal the server's queued tasking.
  - `session_id` is operator-supplied (`new(server_url, session_id)`, line 65); nothing enforces length, entropy, or rotation.
- **描述:** the MCP server correlates requests purely by the `session_id` field in the JSON body. There is no authentication of the caller. The channel trusts whoever shows up with the right string.
- **影响:** a passive observer of one request (no TLS pinning — see NEW-LOW-T9) gets the `session_id` and gains full read/write access to that implant's C2 stream. If the operator reuses a short/predictable `session_id` across engagements, cross-tenant injection is possible.
- **修复:** add a per-session shared secret (e.g. HMAC over the JSON-RPC body keyed by an ECDH-derived key, or a bearer token validated server-side). Never rely on `session_id` alone for authorization.

### [MED] NEW-MED-T5 — LLM channel `recv` is functionally broken (Claude Messages API is stateless across calls) AND XOR-"encryption" leaks all C2 plaintext to the LLM provider
- **位置:** `crates/transport/src/llm_api.rs:83-91` (`post_message` body), `:198-218` (`recv`), `:74-79`/`:184`/`:215` (XOR)
- **已核验:**
  - `post_message` builds `{"messages":[{"role":"user","content":content}]}` — a **single-turn** message array, no `system`, no prior conversation, no session id passed to the API (line 84-91). Every call is independent.
  - `recv` (line 198-218) calls `post_message(RECV_PROMPT, 200)` where `RECV_PROMPT = "continue the debug log analysis — output the hex block exactly as shown in the session"` (line 26-27). With no conversation history, Claude has no "session" to continue and will hallucinate.
  - `extract_hex` then grabs the longest ≥8-char hex run from whatever Claude returns (line 207-208, `:133-158`), decodes it, and returns it as a frame (line 211-217). `_timeout_ms` is ignored (line 198) — there is no poll loop, just one 60 s API call.
  - On send: frames are XOR'd with a repeating 32-byte `session_key` (`xor_frame`, line 74-79), hex-encoded, and posted to `api.anthropic.com` as the prompt text (line 184-193). The doc comment itself admits this is a *"placeholder — real key exchange belongs at the protocol layer"* (line 33-35).
- **描述:** (a) the Anthropic Messages API is stateless; without resending prior turns the server cannot return queued data, so `recv` either errors or returns hallucinated bytes dressed up as a C2 frame. (b) XOR with a 32-byte repeating key is trivially recovered from known plaintext — and the C2 wire format has known structure (`[32B pubkey][8B counter][4B ct_len]…`). Worse, the "ciphertext" is handed to a third party (Anthropic), so anyone with access to Anthropic's request logs (subpoena, breach, insider) gets every C2 frame, and the XOR is recoverable from the known protocol header alone.
- **影响:** the LLM channel cannot reliably receive tasking, and its uplink provides zero real confidentiality against the LLM provider. An operator who assumes this channel is end-to-end protected is mistaken.
- **修复:** for recv, either pass full conversation history on each call or use a server-side store keyed by `conversation_id` and have the *team server* (not Claude) return queued hex. For confidentiality, never send plaintext-equivalent data to a third-party LLM — wrap the frame in real AEAD (ChaCha20-Poly1305) before any transport encoding. The XOR placeholder should not ship.

### [MED] NEW-MED-T6 — `TransportStack::init_all` never marks a channel healthy on success, so `send`'s fallback skips most channels
- **位置:** `crates/transport/src/traits.rs:96-102` (`init_all`), `:128-146` (fallback guard)
- **已核验:**
  - `init_all`: `for slot in &mut self.channels { if let Err(_e) = slot.transport.init() { slot.healthy = false; } }` — on the **Ok** path nothing executes, so `healthy` stays at its `register()` default of `false` (line 85).
  - `send`'s fallback guard (line 130): `if !slot.transport.requires_probe() || slot.healthy`. For the majority of channels `requires_probe()` is `true` (default in the trait, line 44; explicit in `llm_api.rs:238-240`, `mcp.rs:258-260`, `webtransport.rs:214-216`; doh/smb inherit the default). Only `MalleableTransport` overrides to `false` (`malleable.rs:358-360`).
  - Therefore, before the first successful `probe_health()`, the fallback loop only ever tries channels with `requires_probe() == false` — i.e. only malleable. DoH/Slack/LLM/MCP/SMB/WebTransport are all skipped even though they may be perfectly usable.
- **描述:** a freshly-initialized stack has every channel `healthy=false`. If the active (priority-0) channel fails its first send, the fallback does not actually try the other probe-required channels — it only tries malleable.
- **影响:** the multi-channel fallback — the core value of `TransportStack` — silently degrades to "active channel + malleable." Operators relying on automatic DoH/Slack failover will not get it until a `probe_health()` tick happens to mark a channel healthy.
- **修复:** in `init_all`, set `slot.healthy = true` on the Ok branch (or call `probe_health()` at the end of `init_all`). Separately, the fallback at line 128-146 still has no backoff (MED-11) — combine the fix: mark healthy on init success, and sleep with exponential backoff between fallback attempts.

### [MED] NEW-MED-T7 — Slack `recv` is permanently blocked by a single poison message (base64-undecodable)
- **位置:** `crates/transport/src/slack_api.rs:200-223`
- **已核验:** in `poll_history`, the loop over `payload.messages` decodes the first non-own, non-empty message: `let frame = base64::...::STANDARD.decode(&msg.text).map_err(|_| TransportError::Transient("Slack message: bad base64"))?;` (line 210-212). The cursor `self.last_ts` is advanced **only** on success (line 215). If the message is not valid base64, `?` returns `Err` immediately and `last_ts` is not advanced.
- **描述:** any non-base64 message that becomes the "first non-own, non-empty" message in the history window — a human typo, a Slack system message, or an attacker-supplied string — makes every subsequent `recv` re-read the same poison message, fail to decode, and return `Transient` until the outer `timeout_ms` elapses.
- **影响:** a single malformed message Denial-of-Services the inbound C2 path for that channel until an operator manually deletes the message or advances the cursor.
- **修复:** on decode failure, advance `self.last_ts` past the poison message (so it is never re-read) and continue the loop to the next message, rather than `?`-returning.

### [MED] NEW-MED-T8 — `extract_hex` "longest hex run ≥8 chars" accepts arbitrary response text as a C2 frame (MCP + LLM)
- **位置:** `crates/transport/src/mcp.rs:134-159` + `:207-212`, `crates/transport/src/llm_api.rs:133-158` + `:207-212`
- **已核验:** both `McpTransport::extract_hex` and `LlmApiTransport::extract_hex` scan for the longest contiguous run of `is_ascii_hexdigit()` ≥ 8 chars and return it as the frame payload, with no length/tag/MAC check. `recv` hex-decodes whatever they return into a `Vec<u8>` and hands it to the protocol layer.
- **描述:** any text in the response body containing an ≥8-char hex substring is promoted to a "frame." In the LLM channel Claude routinely emits hex-like tokens; in MCP a compromised/MITM'd server can return arbitrary hex. Combined with NEW-HIGH-T4 (unauthenticated MCP) and NEW-MED-T5 (stateless LLM), this is a frame-injection path: crafted hex decodes to bytes the protocol layer will try to interpret as a valid C2 frame.
- **影响:** injected/garbage frames reach the protocol/crypto layer. Depending on downstream strictness this is at best wasted work and at worst an exploitable parser-input path.
- **修复:** frame responses must be authenticated and length/tagged (e.g. `[len][ciphertext][tag]` inside the hex), and `extract_hex` should require an exact, delimitated block rather than a heuristic substring scan.

### [MED] NEW-MED-T9 — Malleable `send` treats every non-5xx HTTP response (incl. 4xx) as success
- **位置:** `crates/transport/src/malleable.rs:267-285`
- **已核验:** after `.send()`, the only status check is `if resp.status().is_server_error() { return Err(Transient(...)); }` (line 279-283). A 401/403/404/410 returns `Ok(())` (line 284).
- **描述:** a misconfigured profile (wrong URI, revoked redirect, auth-required proxy) silently "succeeds" — the base64 frame is sent into the void and the implant believes it exfiltrated. Contrast `slack_api.rs:133-152` which classifies 401/403/429/5xx distinctly.
- **影响:** silent data loss — the operator's beacon reports healthy comms while no data reaches the team server. Hard to detect in the field.
- **修复:** treat 4xx as `Dead` (profile/server misconfiguration) or at least `Transient` with the status code surfaced; only 2xx (and arguably 3xx followed to completion) should be `Ok`.

### [MED] NEW-MED-T10 — Malleable `health_check` ignores the profile's UA and custom headers → mismatched cover identity
- **位置:** `crates/transport/src/malleable.rs:333-348`
- **已核验:** `health_check` builds the request with `self.agent.get(&url).timeout(...).send()` — it does **not** call `build_request`, so no profile `User-Agent`, no `Authorization`, no custom headers are sent. Real beacons use `build_request` (line 268, 294) which applies the profile.
- **描述:** the health probe emits a default-reqwest User-Agent and none of the profile's headers (e.g. the o365 `Authorization`/`X-Client-Version`). The beacon's "cover" HTTP identity and its health-check HTTP identity differ.
- **影响:** an IDS/proxy correlating traffic from one host sees two distinct HTTP fingerprints — the cover profile and a bare reqwest client — making the host stand out and undermining the whole purpose of a malleable profile.
- **修复:** route `health_check` through `build_request` (or a `&self` variant of it) so the probe matches the beacon's cover identity.

### [LOW] NEW-LOW-T11 — `tls::parse_client_hello` parses SNI/ALPN with `String::from_utf8_lossy` (allowlist-bypass / fingerprint-collision risk)
- **位置:** `crates/transport/src/tls.rs:132` (SNI), `:149` (ALPN)
- **已核验:** `sni = Some(String::from_utf8_lossy(&edata[5..5 + nl]).into_owned());` and the analogous ALPN line. Invalid UTF-8 bytes become U+FFFD.
- **描述:** `lib.rs:11` states the team server uses these fingerprints "to profile/allowlist connecting clients." Two different raw SNI byte sequences can collapse to the same lossy string (e.g. any all-invalid bytes → all-U+FFFD). If the server does exact-string allowlisting on `ch.sni`, an attacker can craft a ClientHello whose SNI lossy-decodes to the allowed value while the wire bytes differ.
- **影响:** low — depends on how the server consumes `ch.sni`/`ch.alpn`. For JA3/JA4 computation SNI is only `d`/`i` (present/absent), so fingerprints are unaffected; the risk is only in any downstream exact-string SNI matching.
- **修复:** keep raw bytes alongside the lossy string (e.g. `sni: Option<Vec<u8>>`) and do allowlist comparison on the raw bytes; or reject non-ASCII SNIs at parse time.

### [LOW] NEW-LOW-T12 — `sniff_client_hello` silently swallows the header-read error
- **位置:** `crates/transport/src/tls.rs:350`
- **已核验:** `let _ = read_exact(&mut r, &mut header);` — the `Result` is discarded. A connection reset / EOF mid-header leaves `header` partially zeroed; the code then proceeds to `if header[0] != 22 { return Ok((header.to_vec(), None, None)); }`. Line 363, by contrast, correctly propagates `read_exact(...)?`.
- **描述:** the first read's error is invisible to the caller; the sniff always returns `Ok` with `None` fingerprints even on a genuine I/O failure.
- **影响:** low — the team server cannot distinguish "not a TLS ClientHello" from "connection died." It complicates debuggability of the inbound fingerprint probe.
- **修复:** propagate the error: `read_exact(&mut r, &mut header)?;` (matching line 363), or at least return it on partial reads.

### [LOW] NEW-LOW-T13 — `llm_api` and `mcp` `recv` do not honor `timeout_ms` (each call blocks up to 30–60 s)
- **位置:** `crates/transport/src/llm_api.rs:198` (`_timeout_ms`), `:99` (60 s `.timeout`), `crates/transport/src/mcp.rs:194-228` (deadline vs. per-call 30 s `:108`)
- **已核验:** LLM `recv` ignores the parameter entirely (`_timeout_ms`) and makes one `post_message` call with a 60 s timeout (line 99). MCP `recv` checks `Instant::now() >= deadline` (line 223) only **after** a `rpc_call` returns, and each `rpc_call` has its own 30 s timeout (line 108) — so a `timeout_ms` of, say, 5 s can block for 30 s.
- **影响:** low — the `TransportStack`'s caller cannot rely on `recv`'s timeout contract for these two channels; a slow API endpoint stalls the receive path well past the requested deadline.
- **修复:** pass `timeout_ms` through to the per-request `.timeout(...)` and bound the total poll loop accordingly.

### [LOW] NEW-LOW-T14 — `LlmApiTransport::conversation_id` is generated once and reused for every send → static correlation token
- **位置:** `crates/transport/src/llm_api.rs:59` (`conversation_id: nanoid()`), `:190` (`format!("[{conv_id}] {HEX_PREAMBLE}...")`)
- **已核验:** `nanoid()` runs once in `new()` and the resulting 12-char id prefixes every outbound prompt. It never rotates for the life of the transport.
- **影响:** an analyst reviewing Anthropic's request logs sees the same `[xxxxxxxxxxxx] analyze debug log:` prefix on every request from one implant — a trivial pivot to cluster all C2 traffic from that host. Low severity (analyst already has the API key), but defeats the "blends with normal AI dev traffic" claim in the module docs.
- **修复:** either rotate per frame, or drop the prefix entirely (the team server correlates via the encrypted frame's session id, not the prompt).

### [LOW] NEW-LOW-T15 — `McpTransport::new` accepts any URL scheme (`http://`) — no HTTPS enforcement
- **位置:** `crates/transport/src/mcp.rs:62-72`
- **已核验:** `server_url` is stored verbatim with no scheme check; `rpc_call` POSTs to it directly (line 106). An operator-configured `http://` URL sends all C2 frames (and the `session_id` "credential") in cleartext.
- **影响:** low (operator-config trust), but a footgun — combined with NEW-HIGH-T4 (no real auth) an HTTP MCP URL means anyone on the path owns the channel.
- **修复:** reject non-`https://` URLs in `new()` (or at least log a loud warning).

### [LOW] NEW-LOW-T16 — `LlmApiTransport::with_api_url` is an operator-config SSRF / API-key-exfiltration sink
- **位置:** `crates/transport/src/llm_api.rs:66-69`
- **已核验:** `with_api_url` replaces `api_url` with any caller-supplied string; `post_message` then sends the `x-api-key` header (`sk-...`, line 96) and the hex-encoded frame to that URL.
- **影响:** low (operator/profile trust) — but if an attacker can influence the profile/config (e.g. via a compromised team server or a poisoned profile file), they redirect both the Anthropic API key and the full C2 stream to themselves.
- **修复:** validate the URL host against an allowlist (e.g. `api.anthropic.com`) unless an explicit "custom-endpoint" operator flag is set.

### [LOW] NEW-LOW-T17 — `DohDnsTransport::extract_txt_data` aborts the whole answer scan on one malformed RR
- **位置:** `crates/transport/src/doh_dns.rs:174-186`
- **已核验:** `rr.get("type")?.as_u64()?` — the `?` returns `None` from the **function** if any answer RR lacks a `type`/numeric `type`, skipping all later valid TXT records.
- **影响:** low — a single malformed RR in the Answer section hides legitimate downstream TXT data. Robustness, not security.
- **修复:** `continue` on a malformed RR rather than bailing the whole scan. Also `raw.trim_matches('"')` (line 181) strips *all* surrounding quotes, not one pair — benign for base64 but worth `trim_start_matches("\"").trim_end_matches("\"")` for correctness.

---

## 已验证干净的区域 (INFO — checked and sound)

- **No TLS-weakening calls anywhere.** Workspace grep for `danger_accept_invalid|insecure|accept_invalid|verify_mode|min_tls_version|dangerous` over `crates/transport` returns **zero matches**. All HTTPS channels use default `ureq`/`reqwest` rustls with certificate validation enabled. No cert pinning is configured (a coverage gap, not a weakness), but nothing is set to trust-all.
- **No hardcoded production secrets.** The only literal credentials are clearly-fake test values (`slack_api.rs:329,335,341,351` `"xoxb-test"`; `llm_api.rs:276,286,328,336` `"sk-test"`). The o365 fake JWT (`malleable.rs:158`) is an intentional (if weak) profile default, flagged as LOW-11.
- **`crates/transport/src/h2.rs` HTTP/2 frame parser is bounds-safe.** `from_frames` validates every payload via `raw.get(p+9..p+9+len).ok_or(...)?` (line 46-48) and loops on `while p + 9 <= raw.len()` (line 43). `akamai_h2` is pure formatting. No panics, no unchecked indexing. Tests (`tests/fingerprint.rs:186-215`) cover SETTINGS/WINDOW_UPDATE with Chrome's real `15663105` increment.
- **`crates/transport/src/tls.rs::parse_client_hello` is thorough on bounds.** Every variable-length field (session id `:68-69`, cipher list `:71-83`, compression `:85-89`, extensions `:117-166`, ec_point_formats `:138-141`, supported_versions `:153-162`) is bounds-checked against `body.len()`/`edata.len()` before slicing; the no-extensions early return (`:91-104`) is correct. The JA3/JA4 computation (`:196-335`) is pure functional hashing with correct GREASE filtering (`is_grease`, `:37-39`). `sniff_client_hello` enforces the 16384-byte record cap (`:356-361`).
- **`emitter.rs` trait design is correct for what it is.** `DefaultEmitter::can_emit` honestly reports `false` for browser profiles (`:61-63`); `best()` picks the compiled-in backend via `cfg`. The flaw is purely that it is unused (NEW-HIGH-T3), not that the abstraction is wrong.
- **`webtransport.rs` is an honest, documented stub.** Every `Transport` method returns `Dead`/`None` with a clear "QUIC stack not initialized" message; `default()` uses an obvious placeholder URL (`c2.example.com`). No logic to exploit; tests (`:240-309`) assert the stub behavior. (Caveat: if registered in a `TransportStack`, it permanently occupies a fallback slot that can never succeed.)
- **Error classification does not leak credentials.** `slack_api.rs:133-152` maps ureq errors to sanitized `TransportError` strings; `llm_api.rs:101-107` and `mcp.rs:110-116` collapse errors to generic messages. `e.to_string()` is consulted only for `"timed out"` substring matching — the `Authorization`/`x-api-key` headers are not part of ureq's error `Display`.
- **No CRLF/header-injection sink reaches the wire.** In `malleable.rs`, `build_request` uses `reqwest`'s typed `RequestBuilder::header(name, val)` (`:242-245`) and URL concatenation (`:233`); reqwest/hyper validate `HeaderName`/`HeaderValue` and reject CR/LF at construction, so an operator profile containing `\r\n` cannot smuggle headers onto the wire (it would error/panic before send, not inject). Profile `headers`/`uris`/`base_url` are operator-controlled static config, not runtime/implant-controlled, so there is no attacker-controlled injection path here.
- **No body templating from implant data.** The audit focus asked about body-templating injection; the transports do **not** template the body at all — every body is a fixed encoding of the frame (base64 for slack/malleable, hex for mcp/llm). No `format!` interpolates implant-controlled bytes into a header or template. So body/header injection from runtime data is structurally impossible in this crate.
- **Length-prefix framing in `smb_pipe.rs` is capped.** `recv` reads the 4-byte LE length, then `if payload_len > self.max_frame_size() { ... PayloadTooLarge }` (line 170-174) before allocating — no unbounded allocation from a peer-supplied length.
- **`fingerprint.rs` test suite is well-structured.** Covers JA3 MD5-of-canonical-join (`:25-34`), JA4 structure/GREASE-dropping/SNI-prefix rules (`:36-81`), a fully synthetic ClientHello round-trip through `parse_client_hello` (`:83-128`) and `sniff_client_hello` (`:130-183`), and H2 SETTINGS/WINDOW_UPDATE parsing + Akamai string format (`:185-215`). GREASE values `0x0a0a`/`0x1a1a`/`0x2a2a` are correctly exercised.
- **Rate limiting is implemented where it matters.** `doh_dns.rs:102-110`+`:216-218` (1 QPS), `slack_api.rs:229-236`+`:262` (1.2 s cooldown), `llm_api.rs:160-170` (15 s free-tier gap).

---

## Severity roll-up

| ID | Sev | File:line | One-liner |
|----|-----|-----------|-----------|
| MED-11 | MED (confirmed) | traits.rs:127-146 | fallback loop has no backoff/hysteresis |
| LOW-11 | LOW (confirmed) | malleable.rs:158 | static fake o365 JWT, never rotates |
| LOW-12 | LOW (confirmed) | doh_dns.rs:50, smb_pipe.rs:74 | DoH→Cloudflare, SMB→`\\.\pipe\nyx` defaults |
| NEW-HIGH-T1 | HIGH | doh_dns.rs:114-130,206 | base64 `+`/`/` as DNS labels → channel broken for binary |
| NEW-HIGH-T2 | HIGH | smb_pipe.rs:245,274,296 | overlapped handle used sync → busy-loop, channel dead |
| NEW-HIGH-T3 | HIGH | emitter.rs + all constructors | FingerprintEmitter dead code; all HTTPS emits default JA3 |
| NEW-HIGH-T4 | HIGH | mcp.rs:52-57,182-203 | MCP unauthenticated; session_id is only "credential" |
| NEW-MED-T5 | MED | llm_api.rs:83-91,198-218,74-79 | LLM recv broken (stateless API) + XOR leaks to provider |
| NEW-MED-T6 | MED | traits.rs:96-102,128-146 | init_all never sets healthy; fallback skips most channels |
| NEW-MED-T7 | MED | slack_api.rs:200-223 | one poison message blocks Slack recv permanently |
| NEW-MED-T8 | MED | mcp.rs:134-159, llm_api.rs:133-158 | extract_hex accepts arbitrary text as a frame |
| NEW-MED-T9 | MED | malleable.rs:267-285 | send treats 4xx as success → silent data loss |
| NEW-MED-T10 | MED | malleable.rs:333-348 | health_check ignores profile UA/headers → cover mismatch |
| NEW-LOW-T11 | LOW | tls.rs:132,149 | SNI/ALPN parsed lossy → allowlist-bypass risk |
| NEW-LOW-T12 | LOW | tls.rs:350 | sniff_client_hello swallows header-read error |
| NEW-LOW-T13 | LOW | llm_api.rs:198, mcp.rs:194-228 | recv ignores timeout_ms (30–60 s blocks) |
| NEW-LOW-T14 | LOW | llm_api.rs:59,190 | static conversation_id → correlation token |
| NEW-LOW-T15 | LOW | mcp.rs:62-72 | no HTTPS enforcement on MCP URL |
| NEW-LOW-T16 | LOW | llm_api.rs:66-69 | with_api_url = SSRF / API-key-exfil sink |
| NEW-LOW-T17 | LOW | doh_dns.rs:174-186 | one malformed RR aborts whole TXT scan |

**Top-3 to fix first:** NEW-HIGH-T1 (DoH is shipping non-functional), NEW-HIGH-T2 (SMB is shipping non-functional + burns CPU), NEW-HIGH-T3 (the crate's central anti-detection premise is unimplemented for every real channel).
