# Nyx C2 Framework — Shared Audit Context (2026-07-10 deep pass)

## Authorization
**Nyx** is an **authorized red-team / pentest C2 framework** in Rust (~77K LOC, 25 crates). This audit is for **internal project improvement**. Do NOT include directly weaponizable exploit details or working payloads. Focus on bugs the team must fix: correctness, security, panics, unsafe violations, logic errors, detection-surface IOCs.

## What makes this pass DIFFERENT from the 2026-07-08 audit
The 2026-07-08 audit (see `docs/CODE_AUDIT_2026-07-08_DEEP.md`) found 9 CRIT + 25 HIGH + 39 MED + 39 LOW. **A fix plan is mid-execution** — 37 files have uncommitted changes in the working tree (`git diff`). Your job has THREE parts:

1. **RE-VERIFY every prior finding** at its cited line. Code has moved. State for each: `STILL PRESENT` / `FIXED` / `PARTIALLY FIXED` / `SUPERSEDED` with current line numbers.
2. **AUDIT THE FIXES THEMSELVES** — the uncommitted diff is new code. New code = new bugs. `git diff <file>` to see what changed; scrutinize it for: off-by-one, wrong error handling, new panics, type confusion, incomplete fixes (fixed symptom not root cause), tests that pass but don't actually test the fix.
3. **FIND NEW ISSUES** with fresh eyes — the 07-08 pass missed things. Read code the prior audit called "clean" too.

## How to see what changed (uncommitted fixes)
Run `git diff crates/<path>` to see uncommitted changes to any file. This shows exactly what the fix-in-progress touched. Pay special attention to files in your domain that appear in `git diff --stat`.

## Key architecture facts
- **Two distinct server surfaces:** `POST /beacon` (encrypted implant traffic, binary) vs `GET/POST /api/*` (plaintext JSON operator control API).
- **Wire protocol** is hand-rolled little-endian binary (`crates/protocol/src/wire.rs`). NOT protobuf — deliberate for no_std. Do NOT flag "should use protobuf".
- **Frame layout:** `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B tag]`.
- **Crypto:** X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305; 96-bit nonce = zero-padded counter.
- **Session identity** = implant's 32-byte ephemeral X25519 pubkey.
- `crates/implant-win` is `#![no_std]` + `#![no_main]`, NOT a workspace member; built standalone with nightly + `x86_64-pc-windows-gnu`. `panic = abort`. Don't flag "no std panics".
- Build profile: implant release = `opt-level="z"`, LTO, `panic="abort"`, strip.

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
- **状态:** STILL PRESENT | FIXED | PARTIALLY FIXED | NEW (not in 07-08 baseline)
- **已核验:** what you concretely saw in the code (quote the line / show the diff)
- **描述:** the bug / risk
- **影响:** concrete consequence
- **修复:** specific fix
```
For prior findings, the `状态` field is mandatory.

Also list at end: **已验证干净的区域** (checked and sound) with evidence.

## Workflow
- Use `Read` with offset/limit to page through large files; do NOT read whole 3000-line files blindly.
- Run `git diff <file>` for every file in your domain to see fix-in-progress changes.
- Cite EXACT line numbers from what you actually saw. Every claim grounded in observed code.
- Skip formatters/linters/test-suites — pure static review.
- Write your report to `docs/audit_2026_07_10/<your-domain>.md`.
