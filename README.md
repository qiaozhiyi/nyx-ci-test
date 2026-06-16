# Nyx — a Rust C2 framework (CS-grade extensibility, BRC4-grade stealth)

An authorized red-team / pentest C2 framework that fuses the strengths of the
two commercial benchmarks:

- **Cobalt Strike (4.12/4.13)** — extensibility & UX: Malleable C2, BOF, Kit
  system, UDC2, scripting/REST API, multi-operator.
- **Brute Ratel C4 (v2.2)** — default-on stealth: indirect syscalls, stack
  spoofing, sleep obfuscation, module stomping, AMSI/ETW bypass.

Stack: **Rust full-stack** — team server (`tokio`/`axum`), Windows PIC implant
(nightly/`no_std`, Rustic64/Stardust-style), desktop client (`Tauri` + React),
embedded **Lua/Rune** scripting, protobuf-free hand-rolled wire protocol.

> Full design + phased roadmap: `~/.claude/plans/composed-zooming-wombat.md`.

## Status (P0 — loop proof)

| component | state |
|---|---|
| `crates/protocol` — crypto + framing + codec | ✅ done, 8 unit tests |
| `crates/server` — HTTP beacon listener, sessions, task queue, control API | ✅ done, e2e test green |
| `crates/agent-dev` — std implant (proves the loop on the dev host) | ✅ done |
| `crates/client-cli` — operator REPL | ✅ done |
| `crates/implant-win` — Windows PIC agent (BRC4-grade) | 🟡 scaffolded (needs nightly + Windows toolchain) |
| `crates/client-tauri` — desktop client | 🟡 scaffolded (needs `npm install`) |

The encrypted beacon loop is **verified end-to-end** (ECDH + ChaCha20-Poly1305,
anti-replay, check-in → task queue → task delivery → shell exec → encrypted
response) on macOS via the std dev agent.

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
