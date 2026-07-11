# client-cli — Deep Security Audit (2026-07-08)

**Scope:** `crates/client-cli/src/` — main.rs, rest.rs (~2300 LOC), types.rs, parse.rs, theme.rs, `tui/{mod.rs (~3300), render.rs (~1130), panes.rs (~730), input.rs (~640), session_meta.rs, config.rs, credstore.rs, topology.rs}`, `socks/{mod.rs, handshake.rs, api.rs, relay.rs}`. Plus the shared `crates/rest/src/lib.rs` they all link against.

**Prior baseline:** none of the 25 prior findings touched client-cli (it was UNCOVERED). This is a fresh audit. All findings below are NEW.

**Bottom line:** No RCE-class bugs and no command-injection on the operator host (every "shell" input is JSON-encoded to the team server, never `exec`'d locally). The real risks concentrate in **credential handling** (plaintext-at-rest + cleartext-over-HTTP), **the unauthenticated SOCKS5 listener**, and a handful of robustness gaps that let a malicious team server destabilise the TUI. Logging hygiene around secrets is good — bearer tokens, `/make_token` passwords, and `/creds` secrets are never written to the event stream.

---

## [HIGH] C-1 Plaintext credential storage at rest (`~/.nyx/creds.json`)

- **位置:** `tui/credstore.rs:25-46, 96-145`; ingest trigger at `tui/mod.rs:318-340`.
- **已核验:** `StoredCred { ..., secret: String, ... }` (line 30) is serialized verbatim via `serde_json::to_vec_pretty(&file)` (line 99). The file IS chmod'd 0600 (lines 120-143, fail-closed on chmod error — good) and the dir 0700 best-effort (lines 87-94). But there is **no encryption-at-rest layer** — `secret` lands on disk as `"secret": "P@ssw0rd"` in cleartext JSON. Auto-ingest fires from any parsed cred dump: `/creds <shell-cmd>` (mod.rs:1352-1355 → `run_parsed_shell` → `ParseAs::Creds`) and `/creds sync [reveal]` (mod.rs:1349-1351 → `Cmd::FetchCreds { reveal }` → rest.rs:1327-1378) both land secrets in `self.creds` then `self.creds.save()`.
- **描述:** Captured credentials (hashdump output, `/creds sync reveal` cleartext pull from server, parsed BOF dumps) are persisted to `$HOME/.nyx/creds.json` with no encryption. The 0600 permission is the only control.
- **影响:** For a C2 framework this is a serious attribution + opsec risk. Anything that reads the operator's `$HOME` — backups, sync engines (iCloud Drive / Dropbox / OneDrive mirroring `~/`), EDR on the operator's host, forensic imaging after a seizure, a malware sweep, or a naive `tar ~` — recovers the entire credential vault in cleartext. The 0600 perm stops a casual `cat` from another local user but stops nothing that runs as the operator or reads from a backup/sync copy.
- **修复:** Add an at-rest encryption layer. Recommended: age-style passphrase wrap (argon2id of an operator-supplied unlock passphrase → XChaCha20-Poly1305), with the vault locked/unlocked on `/creds unlock`. At minimum, document the plaintext-at-rest tradeoff loudly in operator docs and add a one-time warning log line on first ingest. Also consider redacting `beacon` and writing the vault outside `$HOME` by default (e.g. `~/.nyx/vault/creds.json.age`).

---

## [HIGH] C-2 Bearer token and fetched cleartext credentials travel over unencrypted HTTP when operator targets a non-loopback http:// URL

- **位置:** `main.rs:20` (default server URL `http://127.0.0.1:8443`); `rest.rs:434-438` (reqwest client build with no `https_only` / no `min_tls` / no redirect policy); `rest.rs:1864-1881` (`authed`); `rest.rs:1332-1336` (`?reveal=1` cleartext creds fetch); shared `crates/rest/src/lib.rs:99-104` (`authed` → `bearer_auth`).
- **已核验:** `Cli::server` is a free-form `String` with default `http://127.0.0.1:8443` (note: `http://` on port 8443, a port conventionally used for TLS). `reqwest::Client::builder().timeout(...).build()` — no `https_only(true)`, no `redirect::Policy::none()`, no cert pinning. `/connect <url>` (mod.rs:1417-1429) and `Cmd::Connect` (rest.rs:454-458) accept any URL with no scheme check. `FetchCreds { reveal: true }` GETs `{srv}/api/creds?reveal=1` and deserializes cleartext `ServerCred { secret }` (rest.rs:84-90, 1338-1368). The bearer token rides `Authorization: Bearer …` on every request (rest.rs:1864-1868).
- **描述:** The client imposes no transport requirement. If an operator runs `nyx-cli --server http://teamserver.example:8443 --token $NYX_TOKEN` (or `/connect http://… <token>` from the TUI), every request — including the bearer token and any `/creds?reveal=1` cleartext pull — goes over plaintext HTTP. There is no warning and no enforcement.
- **影响:** A network-positioned observer (the pivot hop, an egress proxy, an IDS, a compromised router on the operator's path to the team server) captures the bearer token and any revealed credentials. The token is sufficient to drive the entire `/api/*` surface as the operator (CRIT-1's open-mode default server + HIGH-1's hash-then-compare token check on the server side both amplify this — see `_CONTEXT.md` baseline). Default config is loopback so out-of-box there's no leak, but the footgun is one flag away.
- **修复:** (1) Default the client to refusing non-loopback `http://` URLs unless an explicit `--insecure-http` flag is passed, mirroring how curl/wget gate plaintext. (2) Print a one-line warning to the event stream when connecting over plaintext HTTP. (3) Consider offering TLS cert-pin to the team server's long-term key. (4) Document that the SOCKS bridge (socks/mod.rs:82-84) shares the same client builder and inherits the same exposure.

---

## [HIGH] C-3 SOCKS5 listener has no authentication; `--listen 0.0.0.0:…` is a one-flag open-proxy / internal-pivot footgun

- **位置:** `socks/handshake.rs:50-69` (greeting — accepts ONLY method `0x00` NO AUTH); `socks/handshake.rs:75-116` (request — no target allowlist); `socks/mod.rs:74-135` (`run_socks`, default `listen: 127.0.0.1:1080` from main.rs:41-42); `socks/relay.rs:58-146` (`handle_conn`).
- **已核验:** `read_greeting` writes `[05][00]` (method selected = NO AUTH) whenever the client offers `0x00` (line 61-62); there is no username/password (0x02) path. `read_request` accepts CONNECT to any IPv4/IPv6/domain target with no allowlist (lines 91-113). The doc comment (lines 4-7) explicitly dismisses adding auth: *"Supporting SOCKS username/password auth would add nothing: the operator API bearer token already authenticates the bridge to the team server, and the local listener binds to loopback by default."* That reasoning is flawed: the bearer token authenticates **bridge→team-server**, not **socks-client→bridge**. The only gate on the listener is the bind address.
- **描述:** Out-of-box the listener binds loopback, so exposure is limited to other principals on the operator's host. But (a) `--listen 0.0.0.0:1080` (or any non-loopback addr) is a single CLI flag and silently turns the operator's implant into an unauthenticated open proxy / internal-pivot node — anyone who can reach the port gets unrestricted tunneling through the beacon into the victim's internal network, with the operator's beacon taking the attribution; (b) on a multi-user operator host (jump box, shared bastion, container with peer containers), any local principal can TCP-connect to 1080 and pivot; (c) the accept loop spawns an unbounded tokio task per connection (`socks/mod.rs:117`), so even with the `max_chan` cap kicking in at channel-open (`relay.rs:75-82`), a TCP-connection flood to the listener spawns unbounded handshake tasks (no per-peer rate limit, no max-in-flight-handshake cap) — a trivial DoS.
- **影响:** An exposed or shared-host listener gives an unauthenticated attacker a free ride through the operator's beacon: internal SSRF/pivoting, exfiltration, and attribution all land on the operator's implant. The "bridge→server is authed" comment has already prevented this from being fixed.
- **修复:** (1) Add SOCKS username/password auth (RFC 1929, method 0x02) as the default, derived from the operator token or a dedicated `--socks-user/--socks-pass` pair; refuse method 0x00 unless an explicit `--allow-no-auth` flag is set AND the listen address is loopback. (2) Refuse non-loopback `--listen` unless an explicit `--expose` flag is passed (mirror C-2's `--insecure-http` pattern). (3) Cap in-flight handshake tasks (semaphore) and add per-source-IP rate limiting in the accept loop. (4) Fix the misleading doc comment.

---

## [MEDIUM] C-4 Server-controlled session list — unbounded memory growth + `as u16` truncation in render

- **位置:** `tui/mod.rs:265-285` (`poll_worker` replaces `self.sessions` wholesale); `rest.rs:2205-2218` (`session_signature` builds a giant string); `tui/render.rs:253` and `tui/render.rs:751` (`let row_y = area.y + i as u16;`).
- **已核验:** `self.sessions = snap.sessions;` (mod.rs:273) takes whatever the server sends with no cap; `age_baseline` is populated for every session and only retain'd against the live list (lines 277-284). `session_signature` (rest.rs:2205-2218) concatenates `id|hostname|username|is_admin|pending;` for every row into one `String`. In render, `for (i, s) in app.sessions.iter().enumerate() { let row_y = area.y + i as u16; … if row_y >= area.y + area.height { break; } }` (render.rs:252-256, 750-754).
- **描述:** A compromised or buggy team server pushing 100k+ `SessionView` rows causes: (a) the entire `Vec<SessionView>` to clone into App state every signature change; (b) `session_signature` to allocate a multi-MB string each poll; (c) `age_baseline` HashMap to grow unbounded until the next list replaces it; (d) in render, `i as u16` **truncates** once `i >= 65536`, so `row_y` wraps to a small value, the `row_y >= area.y + area.height` break no longer triggers, and the loop re-renders the same first ~65k rows indefinitely — visual corruption plus render-loop CPU saturation.
- **影响:** A malicious team server (or one with a bug that floods the session list) can hang/OOM the operator's TUI. `SessionView.id` is also just a `String` (crates/rest/src/lib.rs:30) — see C-8 for a related panic on crafted ids.
- **修复:** Cap the client-side session list (e.g. drop everything past the first 1000 rows with a "(truncated)" marker). Use `usize`/`u32` consistently for row indices and bound the render loop by `area.height` directly rather than relying on `i as u16` overflow. Consider switching `session_signature` to a hashed digest (e.g. `DefaultHasher` of the concatenated bytes) to avoid the per-poll allocation.

---

## [MEDIUM] C-5 `/upload`, `/bof`, `/inject` slurp entire local file into memory with no size cap

- **位置:** `tui/mod.rs:1526-1544` (`/bof`), `tui/mod.rs:1546-1582` (`/upload`), `tui/mod.rs:1799-1844` (`/inject`).
- **已核验:** All three call `std::fs::read(&file)` returning `Vec<u8>`, then `hex::encode(&data)` which **doubles** the size into a `String`, then pack into a JSON body (`Cmd::Bof { data_hex }` / `Cmd::Upload { data_hex }` / `Cmd::Inject { sc_hex }`). No size guard before the read or the encode.
- **描述:** Pointing any of these at a large file (`/upload /var/log/huge.log`, a multi-GB artifact, or accidentally a special file) loads the full content into RAM and then allocates 2× the file size for the hex string before serialization into the JSON body the worker thread ships to the server. The TUI thread also blocks on `std::fs::read` (sync IO on the UI thread — a UX freeze).
- **影响:** Operator-side OOM / TUI freeze on a typo or a misguided upload. Not network-input-driven, but easy to trigger and the failure mode is silent (no size check, no streaming).
- **修复:** Add an explicit size cap (e.g. refuse >256 MiB with a clear error), and move the `std::fs::read` off the UI thread (send the path to the worker and let it read+hex+post asynchronously, like downloads already stream). For `/upload` specifically, consider streaming in `FileChunk`s like downloads rather than one shot.

---

## [MEDIUM] C-6 Download `local` path written with no sandboxing; `create_dir_all` will mint arbitrary directories

- **位置:** `rest.rs:1802-1860` (`finish_chunked`); `tui/mod.rs:1583-1603` (`/download` parses `local`).
- **已核验:** `let sp = match local { Some(l) if !l.trim().is_empty() => l.clone(), _ => … };` (rest.rs:1817-1823) takes the operator's `local` verbatim. `if let Some(parent) = std::path::Path::new(&save_path).parent() { … let _ = std::fs::create_dir_all(parent); }` (rest.rs:1832-1835) creates any missing parent directories. `std::fs::write(&save_path, &out)` (rest.rs:1837) writes the reassembled file bytes — **attacker-influenced content** (the download comes from the beacon's filesystem via the team server) — to an operator-chosen but unsandboxed path.
- **描述:** `/download C:\Users\victim\secrets.txt ../../.bashrc` (or any traversal/absolute path) writes the remote-controlled bytes there without challenge. `create_dir_all` will silently mint `../../.ssh/` etc. The path is operator-typed so this isn't a classical injection, but the beacon controls the *contents* and the operator may not notice the path is outside `downloads/`.
- **影响:** Operator mistake (typo, copy-paste of a path with `..`) writes attacker-controlled bytes to an arbitrary local path, potentially overwriting dotfiles, SSH keys, or config — especially because the default `downloads/<basename>` derivation is only used when `local` is empty (rest.rs:1818-1822); a non-empty `local` is taken raw.
- **修复:** Refuse `local` paths that escape a configured downloads root unless an explicit override is given; canonicalize and warn if the resolved path is outside `downloads/`. Refuse to write to paths that already exist as a symlink (TOCTOU-safe via `O_CREAT|O_EXCL`).

---
## [LOW] C-7 `worker_loop` panics on reqwest client build failure (`.expect` on the worker thread)

- **位置:** `rest.rs:434-437`.
- **已核验:** `let client = reqwest::Client::builder().timeout(Duration::from_secs(8)).build().expect("reqwest client build");`. This is on the worker thread (`spawn`, rest.rs:363), not the UI thread.
- **描述:** A reqwest client build failure (vanishingly rare — would need a TLS backend init failure) panics the worker thread before the runtime is entered. The TUI stays alive but every later `Cmd::send` lands on a closed channel, surfaced by `send()` (mod.rs:411-415) as `"! worker channel closed — command dropped"`. No clean shutdown of the alternate-screen terminal state.
- **影响:** Operator sees a flood of "command dropped" errors instead of a clean "couldn't initialise HTTP client — exiting". Cosmetic failure mode.
- **修复:** Return the error to the UI via the initial snapshot (the runtime-build-failure path on rest.rs:368-381 already does this — extend the same pattern to the client build), or bubble it out of `spawn` and have `run()` exit with the error before entering the alternate screen.

---

## [LOW] C-8 `rest::short()` byte-slices without char-boundary check (latent panic on server-controlled `SessionView.id`)

- **位置:** `rest.rs:2201-2203`.
- **已核验:** `fn short(s: &str) -> &str { &s[..s.len().min(8)] }`. Called on session ids throughout rest.rs (e.g. lines 472, 503, 708, 778, 817, 881, 1208, …). Contrast with the **safe** version in `tui/mod.rs:2218-2220`: `pub(super) fn short(s: &str) -> String { s.chars().take(8).collect() }`.
- **描述:** `&s[..8]` indexes by **byte**, not char. If `s` starts with a multi-byte UTF-8 codepoint and `s.len() >= 8`, slicing at byte 8 lands mid-codepoint → `panic!("byte index 8 is not a char boundary")`. `SessionView.id` is a free-form `String` from the server (crates/rest/src/lib.rs:30); a malicious/compromised team server can emit a session whose id begins with a multibyte char and the worker thread panics on the first log line that wraps the id.
- **影响:** A crafted `SessionView.id` panics the worker thread. Combined with C-7's send-error path, this silently disconnects the TUI. The mod.rs `short()` is safe; only the rest.rs copy is hazardous.
- **修复:** Replace `&s[..s.len().min(8)]` with `s.chars().take(8).collect::<String>()` (or reuse the mod.rs `short`), making the two copies consistent and panic-free on arbitrary `String` input.

---

## [LOW] C-9 `extract_session_prefix` byte-slices before the ASCII-hex check

- **位置:** `rest.rs:2220-2232`.
- **已核验:** `let prefix = &text[1..end_idx]; if prefix.chars().all(|c| c.is_ascii_hexdigit()) { return Some(prefix.to_string()); }` — the slice happens first, the ASCII check second.
- **描述:** `end_idx` comes from `text.find(']')` (byte position of `]`, an ASCII char, so `end_idx` is a char boundary). Byte 0 is `[` (ASCII, 1 byte) so byte 1 is a char boundary. Therefore `text[1..end_idx]` is currently always on boundaries. The structure is fragile though: if `find(']')` were ever swapped for an operation that could return a non-boundary offset, or if the prefix were sliced from a non-`[` start, the slice would panic before the ASCII check ran.
- **影响:** None today; latent robustness gap.
- **修复:** Reorder to validate boundaries first (`text.is_char_boundary(1) && text.is_char_boundary(end_idx)`), or operate on `chars()` throughout.

---

## [LOW] C-10 `focused_state`/`focused_state_mut` `.expect()` while the terminal is in raw mode

- **位置:** `tui/mod.rs:202-225`.
- **已核验:** Both functions end in `.expect("pane_tree has no leaves — App invariant violated")` (line 212) / `.expect("focused_pane corrected above; tree must have a leaf")` (line 224). These run from `submit()` → `run_shell/run_meta` and from `render()` (via `focused_state().popup_open`, render.rs:75), i.e. while `enable_raw_mode()` is active (mod.rs:2270).
- **描述:** The comment at mod.rs:199-201 acknowledges this: *"P0-4 安全降级：不再无条件 expect (render 期 panic = 终端卡死在 raw mode)"*. The fallback to `leaves().first()` was added, but a final `.expect()` remained as the documented last resort. If any future bug ever empties `pane_tree.leaves()` (close logic, serde roundtrip, etc.), the panic unwinds through `render()` with the terminal still in raw mode — no `disable_raw_mode()` / `LeaveAlternateScreen` / `show_cursor` runs (those are in `run()` after `main_loop` returns, mod.rs:2284-2291), leaving the operator's terminal wedged (no echo, alternate screen, hidden cursor).
- **影响:** Latent: only fires if the App invariant is violated. But the blast radius (wedged terminal) is user-visible and recovery requires `stty sane` / `reset`.
- **修复:** Have `focused_state` return `Option<&PaneState>` and have callers (notably `render_input`/`render_popup`) degrade gracefully (render an empty input box) instead of panicking. Alternatively, install a `std::panic::set_hook` (or catch the unwind around `main_loop`) that restores the terminal before printing the panic.

---

## [LOW] C-11 Dead `_ =>` branch in `render_table`/`render_borderless_table` divides by zero on empty header

- **位置:** `tui/render.rs:449-459` (`render_borderless_table`) and `tui/render.rs:969-980` (`render_table`).
- **已核验:** Both have `match header.len() { 4 => …, 2 => …, _ => (0..header.len()).map(|_| Constraint::Percentage((100 / header.len()) as u16)).collect() }`. If `header.len() == 0`, `100 / 0` panics with integer divide by zero. All current callers pass 2- or 4-element headers (`render_files_table`, `render_procs_table`, `render_creds_table` at render.rs:321/342/364; overlay arms at render.rs:792/807/822/837/853/863/913), so the `_ =>` branch is dead and unreachable today.
- **描述:** A latent panic that a future caller passing an empty `&[&str]` header would trip mid-render (raw mode — see C-10).
- **修复:** Either delete the dead `_ =>` branch (and make the function take a const `N: usize` or an enum), or guard it: `_ if header.is_empty() => Vec::new(), _ => …`. Preferably also assert `header.len() == rows.iter().map(|r| r.len()).max()` so a malformed caller can't crash.

---

## [LOW] C-12 `config.json` written without 0600 (inconsistent with credstore)

- **位置:** `tui/config.rs:39-47`.
- **已核验:** `pub(crate) fn save(&self) -> std::io::Result<()> { … std::fs::write(path, json) }` — no chmod. Contrast `credstore.rs:77-145` which goes to lengths to set 0600/0700 and fail-closed on chmod error.
- **描述:** The config file currently holds only `aliases` + `theme` (no secrets), so the impact is low. But an operator may later add sensitive fields (default token, last server URL with embedded creds, etc.) and the permissive default umask on `std::fs::write` would expose them. The inconsistency with credstore also makes it easy to forget to tighten when secrets land here.
- **影响:** Low today; defense-in-depth gap.
- **修复:** Apply the same 0600 treatment as credstore (or route both through a shared `secure_write` helper). At minimum document that this file must never hold secrets.

---

## [LOW] C-13 `$HOME` unset → credstore silently falls back to cwd (`.`)

- **位置:** `tui/credstore.rs:245-250` (`home_dir`); same pattern at `tui/config.rs:26` and `tui/session_meta.rs:28-33`.
- **已核验:** credstore: `if let Ok(h) = std::env::var("HOME") { return PathBuf::from(h); } PathBuf::from(".")`. config: `std::env::var("HOME").unwrap_or_default()` then `.join(".nyx")…` — if `HOME` is empty, this becomes `./.nyx/config.json`. session_meta: `std::env::var_os("HOME")` with `None => PathBuf::from(".nyx").join("sessions.json")`.
- **描述:** Under launchd/systemd units, cron, or containers without `Environment="HOME=…"`, `$HOME` may be unset or empty. The credstore then writes plaintext credentials to `./creds.json` (the process cwd) — which could be a world-readable dir, a network share, or `/`. No warning is logged. The three modules also disagree on the fallback (credstore → `.`; config → `./.nyx/…`; session_meta → `./.nyx/…`).
- **影响:** Plaintext creds in an unexpected location, silently. Low likelihood but the failure mode is invisible.
- **修复:** Use `dirs::home_dir()` (or `getpwuid_r`) instead of `$HOME`-only, which correctly resolves via the passwd DB on Unix. If that's unavailable, refuse to start with a clear error rather than silently dropping creds in `.`. Make the three modules share one `nyx_home()` helper so they can't drift.

---

## 已验证干净的区域 (checked and sound)

- **No command injection on the operator host.** `Input::Shell(cmd)` (input.rs:376) flows to `run_shell` (mod.rs:1067-1081) which sends `Cmd::Shell { args: cmd, … }` to the worker; the worker packages it as JSON `{"type":"shell","args":…}` (rest.rs:1890-1891) and POSTs it to the team server — it is **never** passed to a local shell. Verified every `run_meta` arm: `/bof`, `/upload`, `/download`, `/inject`, `/make_token`, `/creds`, `/connect`, fileops, etc. all construct JSON bodies via `serde_json::json!`, never `Command::new`/`exec`.
- **No arbitrary deserialization.** `Pane` is `serde::Serialize+Deserialize` (panes.rs) but is **never loaded from disk in production** — `App::new` constructs `Pane::single(1)` fresh (mod.rs:177). The serde impls exist only for a unit test (panes.rs:677-681). `Config`, `CredStore`, `SessionStore` all use typed structs with `#[serde(default)]` or manual `serde_json::Value` field-by-field extraction (session_meta.rs:131-151) — no `Box<dyn Trait>`, no `serde_bytes`, no `bincode`.
- **No path traversal in storage paths.** All three persistent paths are fixed constants (`~/.nyx/config.json`, `~/.nyx/creds.json`, `~/.nyx/sessions.json`); no user input flows into them. (The traversal concern in C-6 is about the *download destination*, a separate path.)
- **SOCKS5 handshake parsing is bounds-safe.** All length-prefixed reads use `read_u8()`/`read_u16()`/`read_exact()` with sizes capped at 255 (nmethods, domain-name length) — no integer overflow, no unbounded allocation (handshake.rs:54-116). `read_u16()` for port is big-endian (network order) per `tokio::io` semantics. Malformed atyp/cmd get the right SOCKS failure reply (0x07/0x08) and bail.
- **No `unsafe` in client-cli.** Verified — the crate contains zero `unsafe` blocks. The shared `crates/rest` is explicitly `#![forbid(unsafe_code)]` (lib.rs:15).
- **Bearer token, make-token passwords, and `/creds` secrets are never logged.** Verified every `log_push`/`self.log` callsite: `/connect` logs the URL only (`connecting to {url} …`, mod.rs:1427); `/make_token` logs `domain\user` only (rest.rs:1208); `/creds add` logs `"cred: added/updated"` (rest.rs:570); `FetchCreds` logs the count only (rest.rs:1343); `AddCred`'s `secret` goes into the JSON body but never into a log line. The queued-tasks overlay (`render.rs:1077-1130`, `task_arg`/`task_detail`) extracts `user`/`pid`/`logon_type` but pointedly **not** `password`.
- **Secret masking in all display paths.** `input::mask(&c.secret)` (input.rs:532-542) is applied in both the pane creds view (render.rs:372) and the fullscreen overlay (render.rs:830). Secrets >4 chars show only first-2/last-2 with `••••` between; ≤4 chars fully masked.
- **Credstore write fails-closed on chmod failure.** credstore.rs:120-143 — if `set_permissions(0600)` fails, the temp file is `remove_file`'d and an `Err` returned; a plaintext world-readable creds file is never left behind. The temp+atomic-rename pattern (lines 102-144) prevents half-written corruption on crash. The earlier "chmod result was `let _ =`-ignored" bug noted in the code comment is fixed.
- **Worker channel send errors are surfaced, not silently dropped.** mod.rs:411-415 — if the worker thread has died, `bridge.cmds.send(cmd)` returns `Err` and the operator sees `"! worker channel closed — command dropped"` in the event stream.
- **Malformed `data_hex` in download chunks aborts instead of corrupting the file.** rest.rs:2166-2184 (and the symmetric rule at socks/mod.rs:190-196 for tunneled channel bytes) — bad hex surfaces as a per-download error rather than silently coercing to empty bytes and producing a corrupt file with a zero-filled hole. This is the right failure mode for a file transfer.
- **reqwest default TLS verification is retained.** No `danger_accept_invalid_certs`, no `min_tls`, no `redirect::Policy::none` anywhere in client-cli or in shared `crates/rest` (grep-verified). The default client does the right thing for `https://` URLs — the exposure in C-2 is specifically about operators who target `http://`.
- **Log/event-stream and history buffers are capped.** `LOG_BUFFER_CAP = 2048` (rest.rs:21) with drain-on-overflow (rest.rs:2245-2248); `STREAM_CAP` similarly caps the UI stream (mod.rs:255-258); `HISTORY_CAP` caps command history (mod.rs:1054-1058). A chatty server can't grow these without bound.
- **`CredStore::load` degrades gracefully on corruption.** credstore.rs:57-68 — `serde_json::from_slice(…).unwrap_or_default()` returns an empty store on parse failure instead of crashing the TUI on startup. (Caveat: this silently masks data loss — a corrupted creds.json looks the same as an empty one. Acceptable tradeoff for "TUI must always start".)

---

## Notes / non-issues explicitly considered

- **"Shell injection" via `format!("cmd /c dir {}", args)` / `format!("ls -l {}", args)` in `run_parsed_shell` (mod.rs:2042-2066).** The `args` is operator-typed and the resulting string runs on the **implant** (sent as a `Shell` task to the team server), not on the operator host. The operator already has unrestricted shell via `!`-prefix / plain shell input (input.rs:559-566), so metacharacter interpretation on the implant is intended behaviour, not injection. The only twist — a malicious `SessionView.os` containing "windows" redirects `/ls` from `ls -l` to `cmd /c dir` — changes which parser runs on the output but doesn't escalate privilege. Not a finding.
- **`reqwest` JSON deserialization on attacker-controlled `/api/*` responses.** Every `.json::<T>()` call propagates errors via `?` (rest.rs:1876-1881, 1908-1923, etc.) and surfaces them as `! <thing> parse: {e}` log lines — no `.unwrap()` on response bodies. The typed structs (`SessionView`, `TaskAck`, `ResultView`, `ServerCred`, `AuditRow`, `ProfileSummary`, `TaskRow`, `AuditVerifyResponse`) all use `#[serde(default)]` for additive fields (crates/rest/src/lib.rs:31-55, 63-64, 73-78; rest.rs:69-116) so a server adding a field degrades gracefully rather than failing.
- **SOCKS accept-loop unbounded `tokio::spawn`.** Folded into C-3 (the listener DoS surface is part of the same unauthenticated-listener problem). Not a separate finding.
