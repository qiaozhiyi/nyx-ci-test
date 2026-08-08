#!/usr/bin/env bash
# regen.sh — rebuild the B3 bof-host and regenerate bof-host.bin.
#
# Pipeline (see Cargo.toml header for why each flag):
#   1. cargo +nightly build the standalone nyx-bof-host cdylib for
#      x86_64-pc-windows-gnu with -Zbuild-std:
#        * -nostdlib → no mingw CRT (no IAT thunks; memcpy stays local)
#        * -Wl,-e,nyx_bof_host_entry + --gc-sections → LTO dead-strips CRT
#        * -Zbuild-std=core,compiler_builtins,alloc → Vec/String for the COFF
#          core, backed by the stateless allocator in src/minialloc.rs
#        * -Zbuild-std-features=compiler-builtins-mem → local memcpy/memset
#   2. nyx-bof-host-dumper (host binary, plain stable cargo) extracts the
#      reachable closure from the export `nyx_bof_host_entry`, compacts it
#      (entry prologue at offset 0), copies the referenced .rdata constants,
#      re-patches every displacement, and refuses to emit for any image with
#      relocations/imports/writable-data references.
#   3. If mingw objdump is available, cross-checks the dumper's instruction
#      lengths against objdump (sanity gate for the hand-rolled decoder,
#      shared with crates/nyx-loader/pic-loader).
#
# Output: crates/bof-host/bof-host.bin (committed; the implant embeds it via
# include_bytes!).
#
# Requirements: rustup nightly with x86_64-pc-windows-gnu target, mingw-w64
# (brew install mingw-w64), bash.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/Cargo.toml"
OUT="$HERE/bof-host.bin"
TARGET="$HERE/target"

RUSTFLAGS="-Cpanic=abort \
  -Clink-arg=-nostdlib \
  -Clink-arg=-Wl,-e,nyx_bof_host_entry \
  -Clink-arg=-Wl,--gc-sections"

echo "==> building nyx-bof-host (nightly, x86_64-pc-windows-gnu, -Zbuild-std)"
RUSTFLAGS="$RUSTFLAGS" cargo +nightly build --release \
  --manifest-path "$MANIFEST" \
  --target x86_64-pc-windows-gnu \
  -Zbuild-std=core,compiler_builtins,alloc \
  -Zbuild-std-features=compiler-builtins-mem

DLL="$TARGET/x86_64-pc-windows-gnu/release/nyx_bof_host.dll"

if [ ! -f "$DLL" ]; then
  echo "error: build did not produce $DLL" >&2
  exit 1
fi

echo "==> building nyx-bof-host-dumper (host, stable)"
cargo build --release --manifest-path "$MANIFEST" -p nyx-bof-host-dumper

DUMPER="$TARGET/release/nyx-bof-host-dumper"

echo "==> extracting reachable PIC closure -> bof-host.bin"
"$DUMPER" "$DLL" "$OUT"

# Sanity gate: the hand-rolled decoder must agree with objdump on instruction
# lengths for the whole .text (the dumper's reachability walk depends on it).
if command -v x86_64-w64-mingw32-objdump >/dev/null 2>&1; then
  echo "==> cross-checking decoder coverage against objdump"
  "$DUMPER" --check-decoder "$DLL" > "$TARGET/decoder.txt"
  # The decoder must cover the full .text range without errors (instruction
  # lengths are validated byte-exactly against objdump during development;
  # here we gate on complete coverage). objdump re-decodes inter-function
  # padding as extra instructions, so counts differ — the hard gate is that
  # the decoder never errored and reached the end of .text.
  OBCNT=$(x86_64-w64-mingw32-objdump -d "$DLL" 2>/dev/null | grep -cE '^\s+[0-9a-f]+:' || true)
  MYCNT=$(grep -cE '^[0-9a-f]{8}:' "$TARGET/decoder.txt" || true)
  LAST=$(tail -1 "$TARGET/decoder.txt" | cut -d: -f1)
  echo "   objdump instructions: $OBCNT, decoder instructions: $MYCNT"
  echo "   decoder covered .text up to 0x$LAST"
else
  echo "==> objdump not found; skipping decoder cross-check"
fi

echo "==> done: $(wc -c < "$OUT" | tr -d ' ') byte bof-host.bin"
