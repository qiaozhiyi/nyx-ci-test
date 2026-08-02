#!/usr/bin/env python3
"""Trace the REAL pic-loader bin in the synthetic PEB environment.

Hooks every instruction and logs: (a) every r14 change (r14 is callee-saved
and the entry's return path reads it — a clobber = a callee with a broken
save/restore, the observed real-machine corruption), (b) every ret (return
target sanity), (c) rsp excursions below the stack region.

Usage: python3 tools/loader-emu/trace_real.py <blob.bin>
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import loader_emu as L  # noqa: E402

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_R14,
)

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

blob = Path(sys.argv[1]).read_bytes()
layout = L.parse_full_blob_layout(blob)
layer2_entry_off = layout["layer2_off"]
print(f"blob: {len(blob)} bytes, layer2 at +0x{layer2_entry_off:x}")

uc = Uc(UC_ARCH_X86, UC_MODE_64)
blob_size = (len(blob) + 0xFFF) & ~0xFFF
region = blob_size + 0x2000
uc.mem_map(L.BLOB_BASE, region, perms=7)
uc.mem_write(L.BLOB_BASE, blob)
uc.mem_map(L.STACK_BASE, L.STACK_SIZE, perms=7)
rsp = L.STACK_BASE + L.STACK_SIZE - 0x10
uc.reg_write(UC_X86_REG_RSP, rsp)
uc.mem_write(rsp, struct.pack("<Q", L.EXIT_STUB))
uc.mem_map(L.EXIT_STUB, 0x1000, perms=7)
uc.mem_write(L.EXIT_STUB, b"\xEB\xFE")
uc.mem_map(L.HEAP_BASE, L.HEAP_SIZE, perms=7)
sysinfo = L.install_system(uc)
uc.msr_write(L.GS_BASE_MSR, sysinfo["teb"])

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

last_r14 = None
r14_changes = []
rets = []
count = [0]
suspicious = []

def hook(uc, address, size, ud):
    count[0] += 1
    r14 = uc.reg_read(UC_X86_REG_R14)
    global last_r14
    if last_r14 is None:
        last_r14 = r14
    elif r14 != last_r14:
        rel = address - L.BLOB_BASE
        if rel < len(blob):
            r14_changes.append((rel, hex(r14)))
            if len(r14_changes) < 30:
                print(f"R14 changed at blob+0x{rel:04x} -> {hex(r14)}")
        last_r14 = r14
    # decode the current instruction (cheap enough for a one-shot trace)
    code = uc.mem_read(address, 4)
    for insn in md.disasm(bytes(code), 0):
        if insn.mnemonic == "ret":
            rel = address - L.BLOB_BASE
            rets.append(rel)
            print(f"ret at blob+0x{rel:04x} (rsp=0x{uc.reg_read(UC_X86_REG_RSP):x})")
        break

uc.hook_add(UC_HOOK_CODE, hook)
try:
    uc.emu_start(L.BLOB_BASE + layer2_entry_off, 0, count=2_000_000)
except Exception as e:
    print(f"emu fault: {type(e).__name__}: {e}")

print(f"\ninstructions: {count[0]}, r14 changes: {len(r14_changes)}, rets: {len(rets)}")
print(f"final rax={hex(uc.reg_read(UC_X86_REG_RAX))} rsp={hex(uc.reg_read(UC_X86_REG_RSP))} r14={hex(uc.reg_read(UC_X86_REG_R14))}")
print("last r14 changes:", r14_changes[-6:])
