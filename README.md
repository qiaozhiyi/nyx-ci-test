# Nyx — a Rust C2 framework (CS-grade extensibility, BRC4-grade stealth)

An authorized red-team / pentest C2 framework that fuses the strengths of the
two commercial benchmarks:

- **Cobalt Strike (4.12/4.13)** — extensibility & UX: Malleable C2, BOF, Kit
  system, UDC2, scripting/REST API, multi-operator.
- **Brute Ratel C4 (v2.2)** — default-on stealth: indirect syscalls, stack
  spoofing, sleep obfuscation, module stomping, AMSI/ETW bypass.

Stack: **Rust full-stack** — team server (`tokio`/`axum`), Windows PIC implant
(nightly/`no_std`, Rustic64/Stardust-style), desktop client (**Makepad**,
`crates/client-ui`) + operator TUI (`crates/client-cli`, ratatui), embedded
**Rhai** scripting, hand-rolled little-endian binary wire protocol (no
serde/prost footprint so the same `protocol` crate compiles `no_std`). No
Node/JS anywhere.

> **Current, code-verified status: [`docs/STATUS.md`](docs/STATUS.md)** (single
> source of truth). Historical audit/research docs are in `docs/archive/`.

## Status (P2 stealth — done & verified on real hardware)

| component | state |
|---|---|
| `crates/protocol` — crypto + framing + codec | ✅ done (X25519+HKDF+ChaCha20-Poly1305, direction-disjoint nonces, anti-replay under write-guard, layered DoS caps) |
| `crates/server` — HTTP beacon listener, sessions, task queue, control API | ✅ done (bearer/named-operator auth, JA3/JA4 TLS sniffing, cred store, hash-chain audit) |
| `crates/agent-dev` — std implant (proves the loop on the dev host) | ✅ done |
| `crates/client-cli` — operator TUI/REPL (ratatui) + headless SOCKS5 relay | ✅ done (full tasking surface incl. token ops, `/creds sync`, `/audit`) |
| `crates/client-ui` — desktop client (Makepad; sole native GUI) | ✅ functional (BOF file loader, token ops, creds/audit sync, env-token) |
| `crates/implant-win` — Windows PIC agent (BRC4-grade) | ✅ **~16k LOC**, 48 selftests, all 25 `Command`s dispatched (incl. `StealToken`/`MakeToken`/`Rev2Self`/`GetUid`); indirect syscalls + HWBP/AMSI/ETW blind + NTDLL unhook + Foliage sleep mask (heap+text) + module-stomp inject + anti-debug, all default-ARMED |
| `crates/operator-kernelsdk` — kernel-tier EDR bypass | ✅ BYOVD (KslD→RTCore64) + ETW-TI blind + DKOM hide + selective callback repurpose + 2/3 PatchGuard windows + MiniFilter-reachable; 7/7 real-machine PASS on Server 2019 |

The encrypted beacon loop is **verified end-to-end** (ECDH + ChaCha20-Poly1305,
anti-replay, check-in → task queue → task delivery → shell exec → encrypted
response) on macOS via the std dev agent. Overall completion **~95%** — gaps
G1-G5 closed 2026-06-27 (postex token-ops wired & real-machine verified, client
creds/audit sync, client-ui BOF loader + env token, MiniFilter reachable,
offset-resolver symbol-server download). Only **G6** remains: Win11 24H2/25H2
real-machine verify (hardware gap — no such host in sshconfig). See
`docs/STATUS.md` for the authoritative status.

## Persistence & guardrails (team server env)

| var | purpose |
|---|---|
| `NYX_BIND` | bind addr (default `0.0.0.0:8443`) |
| `NYX_KEYFILE` | persist the server's long-term X25519 identity to a 0600 file so live sessions **survive a restart** (ephemeral per-process otherwise) |
| `NYX_TOKEN` | if set, every `/api/*` request must carry `Authorization: Bearer <token>` (constant-time compare); `/beacon` is exempt (implants auth cryptographically) |
| `NYX_KILLDATE` | Unix-seconds burn switch — once wall-clock passes it, the server refuses beacons (checked at boot **and** on every beacon) |
| `NYX_PROFILE` | Malleable C2 profile (`c2lint`-validated on load) |
| `NYX_SCRIPT` | Rhai event-hook script (`on_session_new` / `on_result` / `on_session_exit`) |

In-memory DoS caps: `MAX_SESSIONS` (registry), `MAX_PENDING_PER_SESSION` (task queue → 503 back-pressure), `MAX_RESULTS_PER_SESSION` (oldest-evicted). Beacon body capped at 512 KiB (one frame); operator API at 4 MiB.

## Build & test

```bash
cargo test --workspace           # protocol + server e2e (green)
cargo run --release -p nyx-server          # team server on 0.0.0.0:8443
NYX_SERVER_PUB=<pubkey> NYX_SERVER=http://127.0.0.1:8443 cargo run --release -p nyx-agent-dev
cargo run -p nyx-cli -- --server http://127.0.0.1:8443 list
```

## Wire protocol (per request body)

`[32B session pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B Poly1305 tag]`

- session key = `HKDF-SHA256(ECDH(implant_eph, server_id), bound to both pubkeys)`
- AEAD = ChaCha20-Poly1305, 96-bit nonce = zero-padded counter; pubkey is the AAD.
- anti-replay via monotonic counter; pubkey both identifies and keys the session.

## Roadmap

P1 (CS extensibility): Malleable C2 DSL + `c2lint`, BOF loader (CS ABI),
Sleepmask/ProcessInject kits, SMB/TCP P2P, SOCKS5.
P2 (BRC4 stealth): Evasion Kit (indirect syscalls, stack spoof, sleep obfuscation,
module stomping, AMSI/ETW, NTDLL unhook), UDRL, per-build encrypted config.
P3 (team & automation): multiplayer, REST/gRPC, Lua scripting, LDAP, lateral postex, UDC2.
P4 (hardening): auth/killdate, reproducible builds, redirector infra, QUIC, Linux/macOS agent.

## Responsible use

For authorized security testing and research only. Do not deploy against systems
you do not own or are not explicitly authorized to test.
