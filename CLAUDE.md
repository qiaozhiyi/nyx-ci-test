# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Nyx** — an authorized red-team / pentest C2 framework, Rust full-stack. P0 (the encrypted
beacon loop) is done and verified end-to-end on the dev host. The roadmap fuses Cobalt Strike's
extensibility with Brute Ratel C4's default-on stealth; see `README.md` and the full design at
`~/.claude/plans/composed-zooming-wombat.md`. For authorized security testing only.

## Build & test

```bash
cargo test --workspace                 # all tests: 8 protocol (nyx-protocol) + 1 e2e (nyx-server)

# single test
cargo test -p nyx-protocol frame_seal_open_roundtrip
cargo test -p nyx-server checkin_then_shell_task_roundtrips

cargo build --workspace                # build everything in the workspace
```

### Run the loop locally (three terminals)

```bash
# 1. team server — binds 0.0.0.0:8443 (override with NYX_BIND). It logs its `server_pub` hex
#    on startup; that hex is the key the agent needs. Keypair is ephemeral per start.
cargo run --release -p nyx-server

# 2. dev agent — needs the server's pubkey hex (NYX_SERVER_PUB, hex) to derive the session key.
NYX_SERVER_PUB=<pubkey-from-server-logs> cargo run -p nyx-agent-dev

# 3. operator CLI — talks to the plaintext control API
cargo run -p nyx-cli -- list                                  # one-shot: list sessions
cargo run -p nyx-cli -- shell <session-hex> "whoami"          # one-shot: task + poll output
cargo run -p nyx-cli -- repl                                  # interactive (default if no subcommand)
```

Toolchain is pinned to **stable** (`rust-toolchain.toml`). The Windows PIC implant
(`crates/implant-win`) is **not** a workspace member and doesn't build here (see below). The
desktop client is pure-Rust **egui** (`crates/client`) — no Node/JS anywhere in the project.

## Architecture: the beacon loop

There are two distinct surfaces on the team server — keep them separate:

- **`POST /beacon`** — encrypted implant traffic. Binary frame body, never JSON.
- **`GET/POST /api/*`** (`/api/sessions`, `/api/task`, `/api/tasks`, `/api/results`,
  `/api/profile`) — plaintext JSON, the **operator** control API. The CLI, the egui client, and
  tests all drive the loop through it.

A session's identity is the **implant's 32-byte ephemeral X25519 public key**. That pubkey does
three jobs at once: it identifies the session, it is the AEAD AAD on every frame, and the server
derives the per-session key from it on first contact. This makes the beacon handler almost
stateless per request: read pubkey → derive-or-look-up key → decrypt.

**Loop sequence** (`crates/agent-dev/src/lib.rs` is the readable reference): generate eph keypair →
check-in (first message is always `SessionInfo`) → sleep+jitter → POST last cycle's task
responses → receive queued tasks → execute → repeat. Server replies are always an encrypted task
batch (possibly empty).

### Wire protocol (hand-rolled, NOT protobuf)

The plan/design doc mentions protobuf; **the actual implementation is a hand-rolled little-endian
binary codec** (`crates/protocol/src/wire.rs`). This is deliberate so the same `protocol` crate
compiles `no_std` for the position-independent implant without a serde/prost footprint — do not
"fix" this by introducing protobuf.

Frame layout (per request body): `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B tag]`
(`crates/protocol/src/frame.rs`).

Crypto (`crates/protocol/src/crypto.rs`): X25519 ECDH (implant ephemeral × server long-term
identity) → `HKDF-SHA256` bound to both pubkeys → `ChaCha20-Poly1305`; 96-bit nonce = zero-padded
LE counter; anti-replay via monotonic counter checked server-side (`raw.counter <= s.last_recv`
is rejected).

### Crate roles

| crate | role |
|---|---|
| `protocol` | shared by all: crypto, framing, message types + LE codec. The heart of the repo. |
| `server` | team server: `/beacon` listener, session registry, task queue, JSON control API |
| `agent-dev` | **std**-based dev implant — exists only to prove the loop on the dev host (macOS/Linux/Windows). **Not** the production implant. |
| `client-cli` | operator REPL/CLI over the REST API |
| `client` | pure-Rust **egui** desktop client over the REST API (no Node/JS) |
| `implant-win` | scaffolded, **not** a workspace member (see below) |

## Working in this codebase

- **`agent-dev` is the dev harness, not the implant.** It is `std`-based (`ureq`, blocking
  threads) to validate the protocol + server on the dev host. The real Windows PIC implant
  (`crates/implant-win`) reuses only the `protocol` crate.
- **Adding/changing a wire message type touches a hand-mirrored chain, not a derived one.** A new
  `Command`/`Response` variant must be updated in lockstep across: `Command::encode`/`decode`
  (`msg.rs`), the server's `JsonCommand` + `into_command` mapping (`server/src/lib.rs`), and the
  client command surface (CLI / egui client). The wire `Command` enum is broader than the JSON
  operator surface (e.g. `Connect`/`Socks` exist on the wire but have no JSON command yet) — by
  design, narrow it deliberately when wiring up.
- **Server keypair is ephemeral per process.** `AppState::default()` and `main.rs` both call
  `ServerKeypair::generate()`, so the `server_pub` changes every restart and live sessions don't
  survive a restart. Known P0 limitation; persistence is a later-phase item.
- **Tag bytes must stay stable.** Message variants are dispatched on a `u8` tag (`1`=Ping …).
  Reordering or reusing a tag silently breaks the wire format — append new tags, don't renumber.
- **Workspace `[profile.release]`** (`opt-level = "z"`, `lto`, `panic = "abort"`, `strip`) is
  tuned for tiny implant binaries and applies workspace-wide — it affects server/CLI release
  builds too.

## Scaffolded, not built (don't expect them to compile in this workspace)

- **`crates/implant-win`** — Windows position-independent implant skeleton. Gated behind a pinned
  **nightly** toolchain + Windows x86_64 target + the PIC extraction step. It is `#![no_std]`/
  `#![no_main]` and intentionally does **not** compile on the dev host; excluded from the
  workspace to keep it green. Its `src/lib.rs` documents the intended module layout.

(The old `crates/client-tauri` Tauri+React scaffold was removed — the project is pure Rust. The
desktop client is `crates/client`, a pure-Rust egui app.)
