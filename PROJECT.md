# Project: Testing and Review Suite

## Architecture
This project implements a comprehensive testing and review suite for the **Nyx** C2 framework.
- **Operator Interface**: Makepad 2.0 native client (`crates/client-ui`) + ratatui TUI (`crates/client-cli`).
- **Team Server**: axum REST API / beacon loop handler (`crates/server`).
- **Cross-platform Agent**: std-based dev agent (`crates/agent-dev`).
- **Windows PIC Implant**: standalone nightly built PIC implant (`crates/implant-win`).

## Code Layout
- `crates/` - Core Rust crates.
- `scripts/` - Helper and deployment scripts.
- `tools/` - Standalone tools (e.g., sRDI).

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1. Code Review Report | Audit codebase, generate `code_review_report.md` | None | DONE |
| 2 | M2. Visual UI Testing | Automated build & verification scripts for the Makepad client | None | DONE |
| 3 | M3. SSH Connection Automation | Parse `~/.ssh/config` to locate server & verify connection | None | DONE |
| 4 | M4. Remote Functional Testing | Execute tests on Windows server via SSH & output pass/fail report | M3 | DONE |

## Interface Contracts
- **SSH Automation script**:
  - Input: reads `~/.ssh/config` for alias `win` (or customized target alias).
  - Output: Exit code 0 on successful connection and basic command execution.
- **Remote Functional Testing**:
  - Input: established SSH connection to remote Windows server.
  - Output: test logs and report `remote_tests_report.md` indicating pass/fail status.
