#!/usr/bin/env python3
"""Headless Nyx loader probe — Unicorn-based, runs the REAL Layer-1 bytes.

Why: the release-blocking loader probe (scripts/release/loader_probe_gate.ps1)
needs an interactive Windows session (rundll32 hangs in Session 0 on hosted
runners). This probe executes the actual emitted Layer-1 PIC bytes in a Unicorn
x86-64 emulator on ANY host (macOS/Linux/Windows), with a synthetic PEB-free
layout — Layer 1 only needs its own bytes + the NYX2 header to scan, so no OS
emulation is required.

The LAYER1_BOOTSTRAP bytes are parsed directly out of
crates/nyx-loader/src/on_target.rs (single source of truth — zero drift).

Tests:
  1. magic-present blob: Layer-1 self-locates, XOR-recovers the NYX2 magic,
     scans to the header, parses enc_len/nonce/ct pointers into eax/rsi/rdi/rbx
     and jumps to the Layer-2 entry (sentinel `ret` here). Asserts registers.
  2. magic-absent blob: the bounded scan bails with `ret` (offset 0x26), never
     reaches Layer-2 — the fail-loud contract.

Usage:  python3 tools/loader-emu/loader_emu.py
Exit 0 = both contracts hold. This is the future host-side probe gate for
release.yml; once a real Layer-2 (pic-loader) exists, feed the full blob and
assert DllMain reached instead of the sentinel.
"""
import re
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_RIP, UC_X86_REG_RSP,
)

REPO = Path(__file__).resolve().parents[2]
ON_TARGET = REPO / "crates/nyx-loader/src/on_target.rs"

BLOB_BASE = 0x1_0000
STACK_BASE = 0x40_0000
STACK_SIZE = 0x2000
MAGIC = b"NYX2"
MAGIC_XOR_KEY = 0x5A5A5A5A
SCAN_BOUND = 0x100
LAYER2_ENTRY_OFF = 0x80  # synthetic layer-2 entry (sentinel `ret`)


def layer1_bytes() -> bytes:
    """Parse the LAYER1_BOOTSTRAP byte list out of on_target.rs.

    Comments are stripped first: the annotated disassembly contains hex like
    `0x68020314` that must not be captured as bytes.
    """
    src = ON_TARGET.read_text()
    src = re.sub(r"//[^\n]*", "", src)  # drop line comments (hex in disasm annotations)
    m = re.search(r"pub const LAYER1_BOOTSTRAP: &\[u8\] = &\[(.*?)\];", src, re.S)
    assert m, "LAYER1_BOOTSTRAP not found in on_target.rs"
    hexes = re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
    return bytes(int(h, 16) for h in hexes)


def build_blob(with_magic: bool) -> bytes:
    layer1 = layer1_bytes()
    header = MAGIC + (0x100).to_bytes(4, "little") + b"\x00" * (16 + 16 + 16)
    payload = bytearray(layer1 + header)
    if with_magic:
        # Patch the Layer-2 jmp displacement (placeholder zeros in the const)
        # to land on the synthetic layer-2 entry, exactly as the emitter does
        # for real blobs (LAYER2_JMP_OFFSET = 0x35, disp at 0x36).
        disp = LAYER2_ENTRY_OFF - (0x35 + 5)
        payload[0x36:0x3A] = disp.to_bytes(4, "little", signed=True)
    else:
        payload = bytearray(layer1 + b"\x00" * 0x100)
    return bytes(payload)


def run_probe(blob: bytes) -> dict:
    """Execute Layer-1 in Unicorn. Returns the post-run register snapshot."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BLOB_BASE, 0x2000, perms=7)  # RWX blob + slack
    uc.mem_write(BLOB_BASE, blob)
    # Layer-1 starts with `call $+5` (self-locate): it pushes a return
    # address, so a mapped stack with RSP pointing into it is required.
    uc.mem_map(STACK_BASE, STACK_SIZE, perms=7)
    rsp = STACK_BASE + STACK_SIZE - 0x10
    uc.reg_write(UC_X86_REG_RSP, rsp)
    # Seed the initial stack slot with the exit-stub address: both the
    # magic-absent bail `ret` (0x26) and any stray pop land on mapped code.
    uc.mem_write(rsp, (0x50_0000).to_bytes(8, "little"))

    # Sentinel at the synthetic Layer-2 entry: `jmp $` so emulation stays put
    # until the hook stops it (a bare `ret` would pop garbage off the stack).
    uc.mem_write(BLOB_BASE + LAYER2_ENTRY_OFF, b"\xEB\xFE")
    # Exit stub for the bail path (Layer-1 `ret` at 0x26 when magic is absent):
    # pre-fill the initial stack slot so the ret lands on mapped code.
    EXIT_STUB = 0x50_0000
    uc.mem_map(EXIT_STUB, 0x1000, perms=7)
    uc.mem_write(EXIT_STUB, b"\xEB\xFE")

    state = {"layer2_reached": False, "bail_ret_seen": False}
    start = BLOB_BASE
    end = BLOB_BASE + 0x2000

    def hook(uc, address, size, user_data):
        if address == BLOB_BASE + LAYER2_ENTRY_OFF:
            state["layer2_reached"] = True
            uc.emu_stop()
        elif address == BLOB_BASE + 0x26:
            state["bail_ret_seen"] = True
        elif address == EXIT_STUB:
            uc.emu_stop()
        elif address >= BLOB_BASE + 0x2000:
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook, None, start, end)
    try:
        uc.emu_start(BLOB_BASE, end, count=10_000_000)
    except Exception as e:  # noqa: BLE001 — surface emulation faults
        state["fault"] = f"{type(e).__name__}: {e}"
    state["rip"] = uc.reg_read(UC_X86_REG_RIP)  # absolute; callers know BLOB_BASE
    state["rax"] = uc.reg_read(UC_X86_REG_RAX)  # enc_len — a VALUE, not a pointer
    for name, reg in (("rbx", UC_X86_REG_RBX),
                      ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI)):
        state[name] = uc.reg_read(reg) - BLOB_BASE
    return state


def main() -> int:
    ok = True
    # Test 1: magic present — scan finds header, parses fields, jumps to L2.
    s = run_probe(build_blob(with_magic=True))
    magic_off = len(layer1_bytes())  # header starts right after Layer-1
    expected = {
        "layer2_reached": True,
        "rax": 0x100,                   # enc_len
        "rbx": magic_off,               # header base
        "rsi": magic_off + 8,           # &nonce
        "rdi": magic_off + 0x14,        # &ciphertext
    }
    print(f"[probe] magic-present: rip=0x{s['rip'] - BLOB_BASE:02x} "
          f"layer2={s['layer2_reached']} eax_len=0x{s['rax']:x} "
          f"rbx=0x{s['rbx']:x} rsi=0x{s['rsi']:x} rdi=0x{s['rdi']:x}")
    for k, v in expected.items():
        if s.get(k) != v:
            print(f"  FAIL {k}: got {s.get(k)!r} want {v!r}")
            ok = False

    # Test 2: magic absent — bounded scan bails at 0x26, no Layer-2 jump.
    s = run_probe(build_blob(with_magic=False))
    print(f"[probe] magic-absent: rip=0x{s['rip'] - BLOB_BASE:02x} "
          f"bail_ret={s['bail_ret_seen']} layer2={s['layer2_reached']}")
    if s["layer2_reached"] or not s["bail_ret_seen"]:
        print(f"  FAIL: expected bail ret at 0x26 (layer2={s['layer2_reached']}, "
              f"bail={s['bail_ret_seen']})")
        ok = False
    if "fault" in s:
        print(f"  note: emulator fault: {s['fault']}")
        ok = False

    print("loader-emu:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
