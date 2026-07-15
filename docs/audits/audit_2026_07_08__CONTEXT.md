# Nyx C2 Framework — Shared Audit Context (2026-07-08 deep pass)

## Authorization
**Nyx** is an **authorized red-team / pentest C2 framework** in Rust (~76K LOC, 24 crates). This audit is for **internal project improvement**. Do NOT include directly weaponizable exploit details or working payloads. Focus on bugs the team must fix: correctness, security, panics, unsafe violations, logic errors, detection-surface IOCs.

## Key architecture facts (from CLAUDE.md — code + STATUS.md win over docs)
- **Two distinct server surfaces — keep separate:**
  - `POST /beacon` — encrypted implant traffic, binary frame body, never JSON.
  - `GET/POST /api/*` (`/api/sessions`, `/api/task`, `/api/tasks`, `/api/results`, `/api/profile`, `/api/creds`, `/api/kernel/*`) — plaintext JSON operator control API.
- **Wire protocol is hand-rolled little-endian binary** (`crates/protocol/src/wire.rs`), NOT protobuf. Deliberate (compiles `no_std` for PIC implant). Do NOT flag "should use protobuf".
- **Frame layout** (`protocol/src/frame.rs`): `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B tag]`.
- **Crypto** (`protocol/src/crypto.rs`): X25519 ECDH (implant eph × server long-term) → HKDF-SHA256 bound to both pubkeys → ChaCha20-Poly1305; 96-bit nonce = zero-padded counter, first byte separates direction.
- **Session identity** = implant's 32-byte ephemeral X25519 pubkey (also AEAD AAD + per-session key derivation).
- `crates/implant-win` is `#![no_std]` + `#![no_main]`, NOT a workspace member; built standalone with nightly + `x86_64-pc-windows-gnu`. `panic = abort`. Don't flag "no std panics".
- Build profile: implant release = `opt-level="z"`, LTO, `panic="abort"`, strip. GUI profile separate.

## Severity rubric
- **CRITICAL** — remote/code-exec, permanent implant death, total opsec failure, data loss, false security guarantee operators rely on.
- **HIGH** — security weakening, correctness bug in a live path, memory safety, detection-surface flaw likely to burn operator.
- **MEDIUM** — robustness/edge-case panic, forensic/attribution gap, moderate IOC.
- **LOW** — minor, hard-to-trigger, code quality, trivial IOC.
- **INFO** — verified-clean areas (balance the report — state what you checked and found sound).

## Output format (per finding)
```
### [SEVERITY] short-title
- **位置:** crates/.../file.rs:LINE-LINE
- **已核验:** what you concretely saw in the code (quote the line)
- **描述:** the bug / risk
- **影响:** concrete consequence
- **修复:** specific fix
```
Also list at the end: **已验证干净的区域** (checked and sound) with evidence.

## Prior 2026-07-08 baseline findings (CONFIRM still present OR note if FIXED — do not just re-report)
- CRIT-1 server open-mode default Admin (`server/lib.rs:767-771`, `main.rs:110-114`)
- CRIT-2 kernel bridge dead code (`main.rs:129` `kernel: None`)
- CRIT-3 T-REX recon all stubs (`trex/mod.rs:779-847`, `assess_user_mode :162-191`)
- CRIT-4 caller_spoof bare 0xC3 fallback (`caller_spoof.rs:135-141`)
- CRIT-5 fluctuation no unwind guard (`fluctuation.rs:66-78`)
- HIGH-1 constant_time_eq hashes-then-compares (`server/lib.rs:446-471`)
- HIGH-2 HKDF empty salt (`protocol/crypto.rs:206`)
- HIGH-3/5 audit log drops command args (`server/lib.rs:1123-1130`)
- HIGH-4 audit detail serialization fork (`server/audit.rs:106-136`)
- HIGH-6 trex/deaddrop 16KiB truncation (`deaddrop.rs:140-141`)
- HIGH-7 trex/melt no arming guard (`melt.rs:133-144`)
- HIGH-8 ntalloc never frees / 16-slab leak (`ntalloc.rs:269`, `:54-71`)
- MED-1..11, LOW-1..12 (see CODE_AUDIT_2026-07-08.md)

**Your job for prior findings in your files:** verify each still exists at the cited lines; if code changed, give the current line and whether the bug persists. Report **NEW** issues not in the baseline.

## Previously UNCOVERED crates (priority — never audited line-by-line)
`client-cli/*` (17 files incl. socks/), `client-ui/*` (Makepad GUI), `coff` crate, `scripting`, `scripting-rhai`, `profile`, `bof-runner`, `store`, `config`, `config-macros`, `agent-dev`, `operator-kernel-cli`, `offset-resolver`, `minidump-assembler`, `pe`. Give these full line-by-line attention.

## Workflow
- Use `read` with line ranges; do NOT read whole 3000-line files blindly — page through.
- Cite EXACT line numbers from what you actually saw. Every claim grounded in observed code.
- Skip formatters/linters/test-suites — pure static review.
- Write your report to `docs/audit_2026_07_08/<your-domain>.md`.
