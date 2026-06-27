# docs/archive — Historical / Superseded Documents

This directory holds documents that are **no longer authoritative**. They are
preserved for history (git moves retain full blame) but must NOT be trusted for
current status — the code has moved past them.

**For the current, code-verified status always read [`../STATUS.md`](../STATUS.md)**
(the single source of truth), then `../../CLAUDE.md` (agent guide).

---

## Why these were archived

The docs tree had accumulated three conflicting audit reports plus many
overlapping status/plan/research documents, and several "recent" reports were
themselves already stale (the `p2-evasion-synced` branch landed fixes —
selective callback-slot targeting, `SPOOF_SWAP_ENABLED=false`, KslD dynamic
device resolution, two real PatchGuard windows — *after* those reports were
written). Rather than let conflicting copies keep drifting, they were moved here
and superseded by one authoritative `STATUS.md`.

---

## Index

### Superseded audit reports (replaced by `../STATUS.md` + this session's audit)

| File | Date | Why archived |
|---|---|---|
| `AUDIT_REPORT_2026_06_26.md` | 2026-06-26 | Earliest full audit; code-safety findings still valid (see `../code-review-2026-06-27.md`), but status claims overtaken. |
| `FULL_AUDIT_REPORT_2026_06_27.md` | 2026-06-27 | Superseded by the 2026-06-27 reconciliation in `../STATUS.md`. |
| `AUDIT_REPORT_FULL_2026_06_28.md` | 2026-06-28 | **Itself now stale**: claimed `SPOOF_SWAP_ENABLED=true` (now false), repurpose "no selective targeting" (now done), KslD "hardcoded MpKsl" (now dynamic), "all PatchGuard windows no-op" (2 of 3 are real). Kept to record the diagnosis, not for facts. |
| `nyx-gap-analysis-cs413-brc4.md` | 2026-06-27 | CS4.13/BRC4 gap analysis; items resolved since. |

### Gap analysis whose CRITICAL/HIGH items are all closed

| File | Why archived |
|---|---|
| `p2-2026-06-gap-analysis.md` | All 5 CRITICAL + 3 HIGH items it tracked are resolved in code; never updated to reflect that. |

### Completed development plans

| File | Why archived |
|---|---|
| `p1-dev-plan-2026-06-27.md` | P1 dev tasks (C1 KslD device / C2 PG windows / B1 heap enum / B2 Foliage heap mask) all completed. |
| `P2_DEV_PLAN.md` | P2 plan — delivered. |
| `p2-next-dev-guidance.md` | 06-26 next-dev guidance. Its top P0s (§2.3 PatchGuard windows, §2.4 repurpose selective-targeting) are both DONE; remaining work tracked more accurately in `../STATUS.md` §5. Superseded. |

### Research-phase artifacts (input that informed implementation, not status)

| File | Why archived |
|---|---|
| `p2-edr-bypass-plan.md` | Layered research plan; implemented. |
| `p2-integration-analysis.md` | Per-kit build specs, research phase. |
| `p2-windows-bypass-research.md` | Technique research notes. |
| `p2-2026-research-addendum.md` | Research addendum. |
| `p2-2026-h2-latest-sweep.md` | H2 technique sweep. |
| `p2-2026-kernel-tier-deepdive.md` | Kernel-tier research dive. |

### One-shot test reports (point-in-time run results)

| File | Why archived |
|---|---|
| `WINDOWS_TEST_HANDOFF.md` | Single test-run handoff. |
| `p2-windows-test-report.md` | Single test-run report. |
| `windows-test-results.md` | Raw Windows test results. |

---

## What is NOT archived (authoritative / current)

These remain in `../` and are kept current (see the plan that reconciled them):

- `../STATUS.md` — **authoritative** current status (single source of truth)
- `../CLAUDE.md` — agent guide (kept in sync with code)
- `../BYPASS_CAPABILITIES.md`, `../BYPASS_DEVELOPMENT_REPORT.md`,
  `../DEVELOPER_HANDOFF_FINAL.md` — capability + handoff docs (corrected)
- `../p2-kernel-tier-status.md`, `../p2-evasion-integration-status.md` —
  short live status pointers (→ `STATUS.md`)
- `../kernel-test-results.md`, `../p2-real-machine-verify-2026-06-27.md` —
  real-machine verification data
- `../p2-2026-06-hwbp-resolve-forwarder-postmortem.md` — accurate postmortem,
  kept as-is (no stale claims)
- `../WINDOWS_DEV.md`, `../code-review-2026-06-27.md`,
  `../p2-benchmark-vs-cs413-brc4-v23.md`,
  `../p2-real-machine-validation-checklist.md`
