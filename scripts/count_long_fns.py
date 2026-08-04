#!/usr/bin/env python3
"""List non-test Rust functions longer than N lines (default 50).

Excludes: selftests.rs, #[cfg(test)] modules, #[test] fns, nyx_selftest* exports.
Usage: python3 scripts/count_long_fns.py [roots...]  (default roots below)
"""
import re, os, sys

THRESH = 50
ROOTS = sys.argv[1:] or ["crates/implant-win/src", "crates/server/src", "crates/transport/src"]
SKIP_FILES = {"selftests.rs"}
FN_RE = re.compile(
    r'^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z0-9_]+)'
)

def funcs(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    out, i, skip_depth = [], 0, None
    # skip_depth: brace depth at which a #[cfg(test)] module opened; None = not in test mod
    depth = 0
    pending_test_attr = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if "#[cfg(test)]" in stripped:
            pending_test_attr = True
        m = FN_RE.match(stripped) if not stripped.startswith("//") else None
        if m and skip_depth is None and not pending_test_attr:
            name = m.group(1)
            fdepth, started, j = 0, False, i
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{": fdepth += 1; started = True
                    elif ch == "}": fdepth -= 1
                if started and fdepth == 0: break
                j += 1
            if not name.startswith("nyx_selftest"):
                out.append((name, j - i + 1, i + 1))
            i = j + 1
            continue
        if m and skip_depth is None and pending_test_attr:
            # #[cfg(test)] directly on a single fn: consume its body without
            # counting it, and do NOT treat its `{` as a test-module opening.
            fdepth, started, j = 0, False, i
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{": fdepth += 1; started = True
                    elif ch == "}": fdepth -= 1
                if started and fdepth == 0: break
                j += 1
            pending_test_attr = False
            i = j + 1
            continue
        if skip_depth is not None and m:
            # function inside cfg(test) module: skip its lines too. This must
            # run BEFORE the generic brace counting below, otherwise the fn's
            # opening `{` inflates `depth` and the module's closing `}` never
            # matches skip_depth, leaking the skip past the end of the module.
            fdepth, started, j = 0, False, i
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{": fdepth += 1; started = True
                    elif ch == "}": fdepth -= 1
                if started and fdepth == 0: break
                j += 1
            i = j + 1
            continue
        for ch in line:
            if ch == "{":
                depth += 1
                if pending_test_attr and skip_depth is None:
                    skip_depth = depth
                pending_test_attr = False
            elif ch == "}":
                if skip_depth is not None and depth == skip_depth:
                    skip_depth = None
                depth -= 1
        if not line.endswith("\\"):
            # Keep the flag across consecutive attribute lines (e.g. `#[cfg(test)]`
            # followed by `mod tests {` on the next line); clear it on any other
            # non-fn, non-mod item so it cannot leak into unrelated code.
            if (
                pending_test_attr
                and not stripped.startswith("#[")
                and "fn" not in stripped
                and not stripped.startswith("mod")
            ):
                pending_test_attr = False
        i += 1
    return out

for root in ROOTS:
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            if not f.endswith(".rs") or f in SKIP_FILES:
                continue
            p = os.path.join(dirpath, f)
            for name, length, line in funcs(p):
                if length > THRESH:
                    print(f"{length:4d}  {p}:{line}  {name}")
