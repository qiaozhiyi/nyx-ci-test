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
  3. synthetic full-blob: [LAYER1][key][NYX2 header][ct||tag][LAYER2] with the
     probe's synthetic Layer-2 (PEB walk + EAT resolution + VirtualAlloc +
     decrypt + DllMain) run against a synthetic OS: TEB/PEB via the GS-base
     MSR (0xC0000101), PEB_LDR_DATA with an InLoadOrderModuleList
     (exe → ntdll.dll → kernel32.dll), and synthetic PE module images whose
     export tables expose VirtualAlloc/VirtualProtect/RtlMoveMemory/… as
     emulated stubs (unicorn hooks). Asserts Layer-2 returns 0 and the
     DllMain-call hook fires with (base, DLL_PROCESS_ATTACH, NULL).
  4. `--blob <path>`: same full-blob environment against a REAL emitter blob
     (definitive layout `[LAYER1(+bridge)][key 32][NYX2 header][ct||tag]
     [LAYER2]`). The probe verifies the emitter's Layer-2 jmp displacement
     lands exactly on the computed Layer-2 offset (layout-drift check), then
     runs the blob and asserts `layer2 returns 0` + DllMain reached. The
     handoff-bridge ABI is detected at the Layer-2 entry: if the emitter has
     not yet appended the bridge to LAYER1_BOOTSTRAP, the probe converts the
     legacy `rax/rbx/rsi/rdi` handoff to the pic-loader ABI
     `rcx=key,rdx=nonce,r8=ct,r9=ct_len` in a code hook (no-op once the real
     bridge lands).

The synthetic full-blob test (3) is the executable proof that the whole loader
plumbing — PEB walk by djb2 hash, export-address-table walk, VirtualAlloc,
decrypt, map, DllMain call — works headless; it stands in for the real
Layer-2 until crates/nyx-loader/pic-loader produces runnable bytes (the probe
then consumes them via `--blob`).

Usage:
  python3 tools/loader-emu/loader_emu.py                     # tests 1-3
  python3 tools/loader-emu/loader_emu.py --blob blob.bin    # + test 4
  python3 tools/loader-emu/loader_emu.py --fixture dll.bin  # test 3 uses an
                                                             # external PE fixture
Exit 0 = all run probes pass; exit 1 = any failure.
"""
import argparse
import re
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_RIP, UC_X86_REG_RSP,
)

REPO = Path(__file__).resolve().parents[2]
ON_TARGET = REPO / "crates/nyx-loader/src/on_target.rs"

# ── Emulated process layout (must not overlap) ─────────────────────────────
BLOB_BASE = 0x1_0000       # blob (Layer-1 + key + header + ct + Layer-2)
STACK_BASE = 0x40_0000     # 16-byte-aligned stack, top slot seeded with EXIT_STUB
STACK_SIZE = 0x2000
EXIT_STUB = 0x50_0000      # `jmp $` — Layer-2's final `ret` lands here
HEAP_BASE = 0x60_0000      # VirtualAlloc bump region (the RWX "system heap")
HEAP_SIZE = 0x80_000
SYS_BASE = 0x70_0000       # synthetic OS: TEB + PEB + PEB_LDR_DATA + entries
EXE_IMG = 0x71_0000        # first module in InLoadOrderModuleList (the exe)
NTDLL_IMG = 0x72_0000
K32_IMG = 0x73_0000        # kernel32.dll — the module the PEB walk matches
IMG_SIZE = 0x4000
STUB_RVA = 0x1800          # export stub bodies live at module base + STUB_RVA

# IA32_GS_BASE — unicorn maps gs:[...] through this MSR (verified on 2.1.x).
GS_BASE_MSR = 0xC0000101

MAGIC = b"NYX2"
MAGIC_XOR_KEY = 0x5A5A5A5A
SCAN_BOUND = 0x100
LAYER2_ENTRY_OFF = 0x80  # synthetic layer-2 entry (sentinel `ret`) for tests 1/2

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

# ── djb2 (case-insensitive, seed 5381, ×33) — mirrors peb_walk::djb2 ───────
def djb2(s: bytes) -> int:
    h = 5381
    for b in s:
        c = b + 32 if 0x41 <= b <= 0x5A else b  # to_ascii_lowercase
        h = (h * 33 + c) & 0xFFFFFFFF
    return h

# Values pinned by on_target::tests (kernel32/VirtualAlloc/LoadLibraryA/
# GetProcAddress) plus the ones the synthetic Layer-2 additionally resolves.
HASH_KERNEL32_DLL = 0x7040EE75
HASH_NTDLL_DLL = 0x22D3B5ED
HASH_VIRTUAL_ALLOC = 0x58DACBD7
HASH_VIRTUAL_PROTECT = 0x8B9EBDCD
HASH_LOAD_LIBRARY_A = 0x0666395B
HASH_GET_PROC_ADDRESS = 0x82172F7F
HASH_RTL_MOVE_MEMORY = 0xBBDADE67

for _name, _v in (("kernel32.dll", HASH_KERNEL32_DLL),
                  ("VirtualAlloc", HASH_VIRTUAL_ALLOC),
                  ("LoadLibraryA", HASH_LOAD_LIBRARY_A),
                  ("GetProcAddress", HASH_GET_PROC_ADDRESS)):
    assert djb2(_name.encode()) == _v, f"hash mismatch for {_name}"
assert djb2(b"ntdll.dll") == HASH_NTDLL_DLL
assert djb2(b"VirtualProtect") == HASH_VIRTUAL_PROTECT
assert djb2(b"RtlMoveMemory") == HASH_RTL_MOVE_MEMORY


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


def find_jmp_offset(layer1: bytes) -> int:
    """Offset of the Layer-2 `jmp rel32` inside LAYER1_BOOTSTRAP.

    The emitter patches the 4-byte displacement at LAYER2_JMP_OFFSET (0x35
    today; moves if the handoff bridge is appended before it). We locate the
    opcode dynamically so the probe tracks whatever the emitter's const says.
    """
    off = layer1.rfind(b"\xE9")
    if off < 0:
        raise ValueError("LAYER1_BOOTSTRAP has no 0xE9 jmp rel32 (Layer-2 jump)")
    return off


def build_blob(with_magic: bool) -> bytes:
    layer1 = layer1_bytes()
    header = MAGIC + (0x100).to_bytes(4, "little") + b"\x00" * (16 + 16 + 16)
    payload = bytearray(layer1 + header)
    if with_magic:
        # Patch the Layer-2 jmp displacement (placeholder zeros in the const)
        # to land on the synthetic layer-2 entry, exactly as the emitter does
        # for real blobs.
        jmp_off = find_jmp_offset(layer1)
        disp = LAYER2_ENTRY_OFF - (jmp_off + 5)
        payload[jmp_off + 1:jmp_off + 5] = disp.to_bytes(4, "little", signed=True)
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
    uc.mem_write(rsp, EXIT_STUB.to_bytes(8, "little"))

    # Sentinel at the synthetic Layer-2 entry: `jmp $` so emulation stays put
    # until the hook stops it (a bare `ret` would pop garbage off the stack).
    uc.mem_write(BLOB_BASE + LAYER2_ENTRY_OFF, b"\xEB\xFE")
    # Exit stub for the bail path (Layer-1 `ret` at 0x26 when magic is absent):
    # pre-fill the initial stack slot so the ret lands on mapped code.
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


# ═══════════════════════════════════════════════════════════════════════════
# Full-blob mode: synthetic Layer-2 + synthetic OS (PEB / LDR / modules)
# ═══════════════════════════════════════════════════════════════════════════

class Asm:
    """Tiny x86-64 assembler for the synthetic Layer-2 fixture shellcode.

    Supports the handful of encodings the layer-2 sequence needs, with
    label-resolved rel8/rel32 jumps. Every byte is hand-checked against the
    x86-64 reference encodings; a mistake surfaces as a unicorn
    invalid-instruction fault or a failed assertion, never a silent pass.
    """

    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.rel8s = []   # (disp_offset, target_label)
        self.rel32s = []  # (disp_offset, target_label)

    def b(self, *chunks):
        for c in chunks:
            self.code.extend(bytes([c]) if isinstance(c, int) else bytes(c))

    def here(self, name=None):
        off = len(self.code)
        if name:
            self.labels[name] = off
        return off

    def rel8(self, target):
        self.rel8s.append((len(self.code), target))
        self.code.append(0)

    def rel32(self, target):
        self.rel32s.append((len(self.code), target))
        self.code.extend(b"\x00\x00\x00\x00")

    def finish(self) -> bytes:
        for off, tgt in self.rel8s:
            disp = self.labels[tgt] - (off + 1)
            assert -128 <= disp <= 127, f"rel8 overflow at {off:#x} -> {tgt}: {disp}"
            self.code[off] = disp & 0xFF
        for off, tgt in self.rel32s:
            disp = self.labels[tgt] - (off + 4)
            self.code[off:off + 4] = (disp & 0xFFFFFFFF).to_bytes(4, "little", signed=True)
        return bytes(self.code)


def _imm32(v: int) -> bytes:
    return struct.pack("<I", v)


def build_layer2() -> bytes:
    """Synthetic Layer-2: PEB walk + EAT resolution + VirtualAlloc + decrypt +
    VirtualProtect + DllMain call, assembled into bare x86-64 PIC bytes.

    Entry ABI (pic-loader contract): rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len.
    Returns 0 on success, 2/3/4/5 on PEB/resolve/alloc/map failure. The XOR
    decrypt is a documented stand-in for the real ChaCha20-Poly1305 (which
    has its own host-side round-trip tests); the loader *plumbing* — hash
    walk, export walk, alloc, copy, entry call — is the contract being probed.
    """
    a = Asm()
    # ── prologue: frame + save ABI args ──────────────────────────────────
    a.b(0x55)                       # push rbp
    a.b(0x48, 0x89, 0xE5)           # mov rbp, rsp
    a.b(0x48, 0x83, 0xEC, 0x28)     # sub rsp, 0x28   (shadow space + scratch)
    a.b(0x48, 0x89, 0xCB)           # mov rbx, rcx    ; key
    a.b(0x49, 0x89, 0xD5)           # mov r13, rdx    ; nonce (ABI fidelity)
    a.b(0x4D, 0x89, 0xC6)           # mov r14, r8     ; ct
    a.b(0x4D, 0x89, 0xCC)           # mov r12, r9     ; ct_len

    # ── PEB walk: kernel32.dll, then ntdll.dll ───────────────────────────
    a.b(0xBF, *_imm32(HASH_KERNEL32_DLL))            # mov edi, hash
    a.b(0xE8); a.rel32("find_module")
    a.b(0x48, 0x85, 0xC9); a.b(0x74); a.rel8("fail_peb")   # test rcx, rcx; jz
    a.b(0x4C, 0x8B, 0x79, 0x30)                      # mov r15, [rcx+0x30] ; kernel32 base
    a.b(0xBF, *_imm32(HASH_NTDLL_DLL))
    a.b(0xE8); a.rel32("find_module")
    a.b(0x48, 0x85, 0xC9); a.b(0x74); a.rel8("fail_peb")   # test rcx, rcx; jz
    a.b(0x48, 0x8B, 0x41, 0x30)                      # mov rax, [rcx+0x30] ; ntdll base
    a.b(0x48, 0x89, 0x45, 0xF8)                      # mov [rbp-0x8], rax
    # fail_peb sits here, in rel8 range of both PEB-walk checks; the skip jmp
    # keeps straight-line execution from falling into it.
    a.b(0xEB); a.rel8("peb_ok")
    a.here("fail_peb")
    a.b(0xB8, 0x02, 0x00, 0x00, 0x00)                # mov eax, 2  (PEB-walk failure)
    a.b(0xE9); a.rel32("done")
    a.here("peb_ok")

    # ── resolve bootstrap exports by EAT walk (all must be non-null) ─────
    a.b(0xBF, *_imm32(HASH_VIRTUAL_ALLOC)); a.b(0xE8); a.rel32("resolve_export")
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fail_res")
    a.b(0x48, 0x89, 0x45, 0xF0)                      # [rbp-0x10] = VirtualAlloc
    a.b(0xBF, *_imm32(HASH_VIRTUAL_PROTECT)); a.b(0xE8); a.rel32("resolve_export")
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fail_res")
    a.b(0x48, 0x89, 0x45, 0xE8)                      # [rbp-0x18] = VirtualProtect
    a.b(0xBF, *_imm32(HASH_LOAD_LIBRARY_A)); a.b(0xE8); a.rel32("resolve_export")
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fail_res")
    a.b(0xBF, *_imm32(HASH_GET_PROC_ADDRESS)); a.b(0xE8); a.rel32("resolve_export")
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fail_res")
    # RtlMoveMemory is resolved from ntdll.dll (its home module) to prove the
    # ntdll entry's export table is walked correctly too.
    a.b(0x4C, 0x8B, 0x7D, 0xF8)                      # mov r15, [rbp-0x8]  ; ntdll base
    a.b(0xBF, *_imm32(HASH_RTL_MOVE_MEMORY)); a.b(0xE8); a.rel32("resolve_export")
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fail_res")
    a.b(0x48, 0x89, 0x45, 0xE0)                      # [rbp-0x20] = RtlMoveMemory
    # fail_res sits here, in rel8 range of every resolve check (the first is
    # ~74B back); the skip jmp keeps straight-line execution from falling in.
    a.b(0xEB); a.rel8("res_ok")
    a.here("fail_res")
    a.b(0xB8, 0x03, 0x00, 0x00, 0x00)                # mov eax, 3  (export resolution failure)
    a.b(0xE9); a.rel32("done")
    a.here("res_ok")

    # ── VirtualAlloc(NULL, ct_len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    a.b(0x31, 0xC9)                                  # xor ecx, ecx
    a.b(0x4C, 0x89, 0xE2)                            # mov rdx, r12
    a.b(0x41, 0xB8, 0x00, 0x30, 0x00, 0x00)          # mov r8d, 0x3000
    a.b(0x41, 0xB9, 0x40, 0x00, 0x00, 0x00)          # mov r9d, 0x40
    a.b(0xFF, 0x55, 0xF0)                            # call [rbp-0x10]
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fail_alloc")
    a.b(0x48, 0x89, 0xC7)                            # mov rdi, rax        ; buf
    # fail_alloc sits here, just past its only use (the skip jmp is a
    # fall-through guard).
    a.b(0xEB); a.rel8("alloc_ok")
    a.here("fail_alloc")
    a.b(0xB8, 0x04, 0x00, 0x00, 0x00)                # mov eax, 4  (VirtualAlloc failure)
    a.b(0xE9); a.rel32("done")
    a.here("alloc_ok")

    # ── RtlMoveMemory(buf, ct, ct_len) — the "map" copy ──────────────────
    a.b(0x48, 0x89, 0xF9)                            # mov rcx, rdi
    a.b(0x4C, 0x89, 0xF2)                            # mov rdx, r14
    a.b(0x4D, 0x89, 0xE0)                            # mov r8, r12
    a.b(0xFF, 0x55, 0xE0)                            # call [rbp-0x20]

    # ── XOR decrypt in place (synthetic ChaCha20 stand-in) ───────────────
    a.b(0x45, 0x31, 0xC0)                            # xor r8d, r8d        ; i = 0
    a.here("dec_loop")
    a.b(0x4D, 0x39, 0xE0); a.b(0x73); a.rel8("dec_done")   # cmp r8, r12; jae
    a.b(0x43, 0x0F, 0xB6, 0x04, 0x06)                # movzx eax, byte [r14+r8]
    a.b(0x45, 0x89, 0xC1)                            # mov r9d, r8d   (REX R+B: src r8, dst r9 — 0x44 would write rcx)
    a.b(0x41, 0x83, 0xE1, 0x1F)                      # and r9d, 31
    a.b(0x42, 0x32, 0x04, 0x0B)                      # xor al, [rbx+r9]     (32 = reg dest; 30 would xor the key byte)
    a.b(0x42, 0x88, 0x04, 0x07)                      # mov [rdi+r8], al
    a.b(0x49, 0xFF, 0xC0)                            # inc r8
    a.b(0xEB); a.rel8("dec_loop")
    a.here("dec_done")

    # ── VirtualProtect(buf, ct_len, PAGE_EXECUTE_READWRITE, &oldprot) ────
    a.b(0x48, 0x89, 0xF9)                            # mov rcx, rdi
    a.b(0x4C, 0x89, 0xE2)                            # mov rdx, r12
    a.b(0x41, 0xB8, 0x40, 0x00, 0x00, 0x00)          # mov r8d, 0x40
    a.b(0x4C, 0x8D, 0x4D, 0xE4)                      # lea r9, [rbp-0x1C]   ; &oldprot
    a.b(0xFF, 0x55, 0xE8)                            # call [rbp-0x18]

    # ── DllMain(base, DLL_PROCESS_ATTACH, NULL) via the PE entry point ───
    a.b(0x8B, 0x47, 0x3C)                            # mov eax, [rdi+0x3C]  ; e_lfanew
    a.b(0x8B, 0x4C, 0x07, 0x28)                      # mov ecx, [rdi+rax+0x28] ; AddressOfEntryPoint
    a.b(0x85, 0xC9); a.b(0x74); a.rel8("fail_map")
    a.b(0x4C, 0x8D, 0x0C, 0x0F)                      # lea r9, [rdi+rcx]    ; entry VA (REX.W+R: base rdi)
    a.b(0x48, 0x89, 0xF9)                            # mov rcx, rdi        ; base
    a.b(0xBA, 0x01, 0x00, 0x00, 0x00)                # mov edx, 1          ; DLL_PROCESS_ATTACH
    a.b(0x45, 0x31, 0xC0)                            # xor r8d, r8d        ; NULL
    a.b(0x41, 0xFF, 0xD1)                            # call r9
    a.b(0x31, 0xC0)                                  # xor eax, eax        ; return 0
    a.b(0xE9); a.rel32("done")

    # ── fail_map + done (reached only by `jz fail_map` above) ────────────
    a.here("fail_map")
    a.b(0xB8, 0x05, 0x00, 0x00, 0x00)                # mov eax, 5  (PE entry missing)
    a.b(0xE9); a.rel32("done")
    a.here("done")
    a.b(0xC9)                                        # leave
    a.b(0xC3)                                        # ret → seeded EXIT_STUB

    # ── find_module: PEB walk by BaseDllName hash ─────────────────────────
    # in: edi = djb2 hash of the target BaseDllName; out: rcx = LdrEntry (0 = miss)
    a.here("find_module")
    a.b(0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00)  # mov rax, gs:[0x60]
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fm_fail")
    a.b(0x48, 0x8B, 0x40, 0x18)                      # mov rax, [rax+0x18]  ; LDR
    a.b(0x48, 0x85, 0xC0); a.b(0x74); a.rel8("fm_fail")
    a.b(0x4C, 0x8D, 0x50, 0x10)                      # lea r10, [rax+0x10]  ; list head
    a.b(0x48, 0x8B, 0x48, 0x10)                      # mov rcx, [rax+0x10]  ; first node
    a.here("fm_loop")
    a.b(0x4C, 0x39, 0xD1); a.b(0x74); a.rel8("fm_fail")   # cmp rcx, r10 (back at head?)
    a.b(0x0F, 0xB7, 0x41, 0x58)                      # movzx eax, word [rcx+0x58] ; length
    a.b(0x85, 0xC0); a.b(0x74); a.rel8("fm_next")
    a.b(0x48, 0x8B, 0x51, 0x60)                      # mov rdx, [rcx+0x60]  ; buffer — UNICODE_STRING pads to 16B (len@0x58, max@0x5A, ptr@0x60)
    a.b(0x48, 0x85, 0xD2); a.b(0x74); a.rel8("fm_next")
    a.b(0xBE, 0x05, 0x15, 0x00, 0x00)                # mov esi, 5381  (djb2 seed 0x1505)
    a.b(0xD1, 0xE8)                                  # shr eax, 1          ; nchars
    a.b(0x74); a.rel8("fm_next")                     # jz
    a.here("fm_char")
    a.b(0x44, 0x0F, 0xB6, 0x1A)                      # movzx r11d, byte [rdx]
    # to_ascii_lowercase: only A-Z get +0x20 (an `or 0x20` would corrupt
    # chars like '_' 0x5F -> 0x7F, breaking the djb2 contract).
    a.b(0x41, 0x80, 0xFB, 0x41); a.b(0x72); a.rel8("fm_lc_skip")  # cmp r11b,'A'; jb
    a.b(0x41, 0x80, 0xFB, 0x5A); a.b(0x77); a.rel8("fm_lc_skip")  # cmp r11b,'Z'; ja
    a.b(0x41, 0x80, 0xC3, 0x20)                      # add r11b, 0x20
    a.here("fm_lc_skip")
    a.b(0x6B, 0xF6, 0x21)                            # imul esi, esi, 33
    a.b(0x44, 0x01, 0xDE)                            # add esi, r11d
    a.b(0x48, 0x83, 0xC2, 0x02)                      # add rdx, 2
    a.b(0xFF, 0xC8)                                  # dec eax
    a.b(0x75); a.rel8("fm_char")
    a.b(0x39, 0xFE)                                  # cmp esi, edi
    a.b(0x74); a.rel8("fm_found")
    a.here("fm_next")
    a.b(0x48, 0x8B, 0x09)                            # mov rcx, [rcx]      ; flink
    a.b(0xEB); a.rel8("fm_loop")
    a.here("fm_fail")
    a.b(0x31, 0xC9)                                  # xor ecx, ecx
    a.here("fm_found")
    a.b(0xC3)                                        # ret

    # ── resolve_export: EAT walk ──────────────────────────────────────────
    # in: r15 = module base, edi = target hash; out: rax = func VA (0 = miss)
    a.here("resolve_export")
    a.b(0x41, 0x8B, 0x47, 0x3C)                      # mov eax, [r15+0x3C]  ; e_lfanew
    a.b(0x49, 0x8D, 0x4C, 0x07, 0x18)                # lea rcx, [r15+rax+24]  ; opt header (REX.W+B: base r15)
    a.b(0x0F, 0xB7, 0x11)                            # movzx edx, word [rcx] ; magic
    a.b(0x66, 0x81, 0xFA, 0x0B, 0x02)                # cmp dx, 0x20B (PE32+)
    a.b(0x75); a.rel8("re_fail")
    a.b(0x44, 0x8B, 0x49, 0x70)                      # mov r9d, [rcx+0x70]  ; export RVA
    a.b(0x45, 0x85, 0xC9); a.b(0x74); a.rel8("re_fail")
    a.b(0x4F, 0x8D, 0x04, 0x0F)                      # lea r8, [r15+r9]     ; export dir (REX.W+R+X+B)
    a.b(0x45, 0x8B, 0x50, 0x20)                      # mov r10d, [r8+0x20]  ; AddressOfNames
    a.b(0x45, 0x8B, 0x58, 0x24)                      # mov r11d, [r8+0x24]  ; AddressOfNameOrdinals
    a.b(0x41, 0x8B, 0x48, 0x1C)                      # mov ecx, [r8+0x1C]   ; AddressOfFunctions
    a.b(0x51)                                        # push rcx  (funcs RVA)
    a.b(0x41, 0x53)                                  # push r11  (ordinals RVA)
    a.b(0x31, 0xF6)                                  # xor esi, esi         ; i = 0
    a.here("re_loop")
    a.b(0x41, 0x3B, 0x70, 0x18); a.b(0x73); a.rel8("re_fail2")  # cmp esi, [r8+0x18]; jae
    a.b(0x4B, 0x8D, 0x04, 0x17)                      # lea rax, [r15+r10]   ; names table (SIB 0x17: index 010=r10, X=1)
    a.b(0x8B, 0x14, 0xB0)                            # mov edx, [rax+rsi*4] ; name RVA
    a.b(0x49, 0x8D, 0x04, 0x17)                      # lea rax, [r15+rdx]   ; name string
    a.b(0xB9, 0x05, 0x15, 0x00, 0x00)                # mov ecx, 5381  (djb2 seed 0x1505)
    a.here("re_hash")
    a.b(0x0F, 0xB6, 0x10)                            # movzx edx, byte [rax]
    a.b(0x84, 0xD2); a.b(0x74); a.rel8("re_hash_done")   # test dl, dl (NUL?)
    # to_ascii_lowercase (A-Z only; see fm_char)
    a.b(0x80, 0xFA, 0x41); a.b(0x72); a.rel8("re_lc_skip")  # cmp dl,'A'; jb
    a.b(0x80, 0xFA, 0x5A); a.b(0x77); a.rel8("re_lc_skip")  # cmp dl,'Z'; ja
    a.b(0x80, 0xC2, 0x20)                            # add dl, 0x20
    a.here("re_lc_skip")
    a.b(0x6B, 0xC9, 0x21)                            # imul ecx, ecx, 33
    a.b(0x01, 0xD1)                                  # add ecx, edx
    a.b(0x48, 0xFF, 0xC0)                            # inc rax
    a.b(0xEB); a.rel8("re_hash")
    a.here("re_hash_done")
    a.b(0x39, 0xF9); a.b(0x75); a.rel8("re_next")   # cmp ecx, edi; jne
    a.b(0x41, 0x5B)                                  # pop r11
    a.b(0x59)                                        # pop rcx
    a.b(0x4B, 0x8D, 0x04, 0x1F)                      # lea rax, [r15+r11]   ; ordinals table (REX.W+X+B)
    a.b(0x0F, 0xB7, 0x14, 0x70)                      # movzx edx, word [rax+rsi*2]
    a.b(0x49, 0x8D, 0x04, 0x0F)                      # lea rax, [r15+rcx]   ; funcs table
    a.b(0x8B, 0x04, 0x90)                            # mov eax, [rax+rdx*4] ; func RVA
    a.b(0x4C, 0x01, 0xF8)                            # add rax, r15        ; -> VA
    a.b(0xC3)                                        # ret
    a.here("re_next")
    a.b(0xFF, 0xC6)                                  # inc esi
    a.b(0xEB); a.rel8("re_loop")
    a.here("re_fail2")
    a.b(0x41, 0x5B)                                  # pop r11
    a.b(0x59)                                        # pop rcx
    a.here("re_fail")
    a.b(0x31, 0xC0)                                  # xor eax, eax
    a.b(0xC3)                                        # ret

    return a.finish()


def build_module_image(base: int, name: str, exports: list) -> bytes:
    """Synthetic PE32+ module with an export directory exposing `exports`.

    Layout: DOS header → NT headers → optional header (PE32+, export dir at
    data dir[0] = RVA 0x1000) → one .edata section → export structures →
    stub bodies (`ret`) at RVA 0x1800, 0x10 apart. The stub bodies are the
    hook-emulated export implementations; unicorn hooks fire at their VAs.
    """
    img = bytearray(0x4000)
    # DOS header
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)          # e_lfanew
    # NT headers
    img[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", img, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    # Optional header (PE32+) at 0x98
    o = 0x98
    struct.pack_into("<H", img, o + 0x00, 0x20B)     # magic
    struct.pack_into("<I", img, o + 0x10, 0)         # AddressOfEntryPoint
    struct.pack_into("<Q", img, o + 0x18, base)      # ImageBase
    struct.pack_into("<I", img, o + 0x20, 0x1000)    # SectionAlignment
    struct.pack_into("<I", img, o + 0x24, 0x200)     # FileAlignment
    struct.pack_into("<HH", img, o + 0x28, 6, 0)     # OS version
    struct.pack_into("<HH", img, o + 0x30, 6, 0)     # subsystem version
    struct.pack_into("<I", img, o + 0x38, 0x4000)    # SizeOfImage
    struct.pack_into("<I", img, o + 0x3C, 0x200)     # SizeOfHeaders
    struct.pack_into("<H", img, o + 0x44, 3)         # Subsystem
    struct.pack_into("<I", img, o + 0x68, 16)        # NumberOfRvaAndSizes
    if exports:
        struct.pack_into("<II", img, o + 0x70, 0x1000, 0x600)  # export dir RVA/size
    # Section header at 0x188
    s = 0x188
    img[s:s + 8] = b".edata\0\0"
    struct.pack_into("<IIIIIIHHI", img, s + 8,
                     0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x40000040)
    if not exports:
        return bytes(img)
    # Export structures live at image offset 0x1000 == RVA 0x1000 (the
    # emulated EAT walk reads base + export_rva, so the section data must be
    # laid out at its virtual address, not its raw file offset).
    n = len(exports)
    dir_off = 0x1000
    names_off = dir_off + 40
    ords_off = names_off + 4 * n
    funcs_off = ords_off + 2 * n
    strs_off = funcs_off + 4 * n
    dllname = name.encode("ascii") + b"\0"
    struct.pack_into("<IIHHIIIIIII", img, dir_off,
                     0, 0, 0, 0, strs_off + len(dllname), 1, n, n,
                     funcs_off, names_off, ords_off)
    img[strs_off:strs_off + len(dllname)] = dllname
    p = strs_off + len(dllname)
    for i, exp in enumerate(exports):
        struct.pack_into("<I", img, names_off + 4 * i, p)
        sbytes = exp.encode("ascii") + b"\0"
        img[p:p + len(sbytes)] = sbytes
        p += len(sbytes)
        struct.pack_into("<H", img, ords_off + 2 * i, i)
        struct.pack_into("<I", img, funcs_off + 4 * i, STUB_RVA + 0x10 * i)
        img[STUB_RVA + 0x10 * i] = 0xC3              # stub body: `ret`
    return bytes(img)


def build_fixture_pe() -> bytes:
    """Tiny synthetic PE32+ DLL for the reflective load: one .text section
    whose entry point is a DllMain stub `mov eax, 1; ret` (returns TRUE).

    The section's PointerToRawData equals its VirtualAddress (0x1000), so the
    file layout == memory layout and the reflective "map" is a straight copy
    of the whole file to the VirtualAlloc'd buffer: the entry-point RVA then
    points exactly at the DllMain stub, which is where the DllMain-call hook
    fires. (Real section mapping + relocs + imports are the pic-loader's job,
    covered by the crate's host-side reflective_load tests.)
    """
    img = bytearray(0x1200)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    img[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", img, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    o = 0x98
    struct.pack_into("<H", img, o + 0x00, 0x20B)
    struct.pack_into("<I", img, o + 0x10, 0x1000)    # AddressOfEntryPoint = .text
    struct.pack_into("<Q", img, o + 0x18, 0x1_8000_0000)  # preferred ImageBase
    struct.pack_into("<I", img, o + 0x20, 0x1000)    # SectionAlignment
    struct.pack_into("<I", img, o + 0x24, 0x200)     # FileAlignment
    struct.pack_into("<HH", img, o + 0x28, 6, 0)
    struct.pack_into("<HH", img, o + 0x30, 6, 0)
    # SizeOfImage must fit the file size: the pic-loader maps into a
    # VirtualAlloc'd buffer of ct_len bytes and rejects size_of_image > len.
    struct.pack_into("<I", img, o + 0x38, 0x1200)    # SizeOfImage == file size
    struct.pack_into("<I", img, o + 0x3C, 0x200)     # SizeOfHeaders
    struct.pack_into("<H", img, o + 0x44, 3)
    struct.pack_into("<I", img, o + 0x68, 16)
    s = 0x188
    img[s:s + 8] = b".text\0\0\0"
    # raw offset == VA (0x1000) so file layout == memory layout.
    struct.pack_into("<IIIIIIHHI", img, s + 8,
                     0x200, 0x1000, 0x200, 0x1000, 0, 0, 0, 0, 0x60000020)
    # DllMain stub at raw 0x1000 (= VA 0x1000): mov eax, 1; ret
    img[0x1000:0x1006] = b"\xB8\x01\x00\x00\x00\xC3"
    return bytes(img)


def pe_entry_rva(data: bytes) -> int:
    if data[:2] != b"MZ":
        raise ValueError("fixture is not a PE file (missing MZ header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("fixture is not a PE file (missing PE signature)")
    if struct.unpack_from("<H", data, e_lfanew + 24)[0] != 0x20B:
        raise ValueError("fixture is not PE32+ (optional-header magic must be 0x20B)")
    return struct.unpack_from("<I", data, e_lfanew + 24 + 16)[0]


def build_full_blob(fixture: bytes):
    """Assemble the definitive-layout blob:
    [LAYER1(+bridge)][key 32][NYX2 magic(4) enc_len(4) nonce(12)][ct||tag][LAYER2]
    The Layer-2 jmp displacement is patched to land at the Layer-2 start.
    """
    layer1 = layer1_bytes()
    key = bytes(range(32))
    nonce = b"NYXNONCE0001"  # 12 bytes
    ct = bytes(b ^ key[i % KEY_LEN] for i, b in enumerate(fixture))
    tag = b"\xAA" * TAG_LEN
    blob = bytearray()
    blob += layer1
    blob += key
    blob += MAGIC + struct.pack("<I", len(fixture)) + nonce
    blob += ct
    blob += tag
    layer2_off = len(blob)
    blob += build_layer2()
    jmp_off = find_jmp_offset(layer1)
    blob[jmp_off + 1:jmp_off + 5] = struct.pack("<i", layer2_off - (jmp_off + 5))
    return bytes(blob), {
        "key": key, "nonce": nonce, "fixture": fixture,
        "header_off": len(layer1) + KEY_LEN, "enc_len": len(fixture),
        "ct_off": len(layer1) + KEY_LEN + 20, "layer2_off": layer2_off,
        "jmp_off": jmp_off,
    }


def parse_full_blob_layout(blob: bytes) -> dict:
    """Validate a REAL emitter blob against the definitive layout and return
    the parsed offsets. Raises ValueError on any drift (fail-loud gate)."""
    layer1 = layer1_bytes()
    header_off = len(layer1) + KEY_LEN
    if len(blob) < header_off + 20:
        raise ValueError(
            f"blob too short ({len(blob)}B) for [LAYER1({len(layer1)}) + key(32) + header(20)]")
    if blob[header_off:header_off + 4] != MAGIC:
        raise ValueError(
            f"NYX2 magic not found at offset {header_off:#x} (= LAYER1+key) — "
            "emitter layout drift (definitive layout: [LAYER1(+bridge)][key 32][NYX2 header])")
    enc_len = struct.unpack_from("<I", blob, header_off + 4)[0]
    ct_off = header_off + 20
    layer2_off = ct_off + enc_len + TAG_LEN
    if layer2_off + 1 > len(blob):
        raise ValueError(
            f"enc_len {enc_len} + {TAG_LEN}B tag overruns blob: layer2 would sit at "
            f"{layer2_off:#x} but blob is {len(blob)}B")
    jmp_off = find_jmp_offset(layer1)
    disp = struct.unpack_from("<i", blob, jmp_off + 1)[0]
    target = jmp_off + 5 + disp
    if target != layer2_off:
        raise ValueError(
            f"Layer-2 jmp target {target:#x} != computed layer2 offset {layer2_off:#x} "
            f"(LAYER1+key+header+ct+tag) — emitter layout drift")
    return {"header_off": header_off, "ct_off": ct_off, "enc_len": enc_len,
            "layer2_off": layer2_off, "jmp_off": jmp_off}


def install_system(uc: Uc) -> dict:
    """Map the synthetic OS and write the PEB/LDR/module structures.

    TEB (gs base) → [0x60] PEB → [0x18] PEB_LDR_DATA → [0x10]
    InLoadOrderModuleList head → exe → ntdll.dll → kernel32.dll (each an
    LDR_DATA_TABLE_ENTRY whose InLoadOrderLinks is its first field, so the
    node pointer IS the entry pointer). DllBase points at synthetic PE images
    with export tables; the export stubs are `ret` bodies the emulator hooks.
    """
    uc.mem_map(SYS_BASE, 0x10000, perms=7)
    teb, peb, ldr = SYS_BASE, SYS_BASE + 0x1000, SYS_BASE + 0x2000
    mods = [
        ("nyx_fixture.exe", EXE_IMG, []),
        ("ntdll.dll", NTDLL_IMG, ["RtlMoveMemory", "RtlZeroMemory"]),
        ("kernel32.dll", K32_IMG,
         ["VirtualAlloc", "VirtualProtect", "LoadLibraryA", "GetProcAddress",
          "RtlMoveMemory"]),
    ]
    order = [m[0] for m in mods]
    bases, exports, entries = {}, {}, {}
    for name, base, exps in mods:
        uc.mem_map(base, IMG_SIZE, perms=7)
        uc.mem_write(base, build_module_image(base, name, exps))
        bases[name] = base
        exports[name] = {e: base + STUB_RVA + 0x10 * i for i, e in enumerate(exps)}
    head = ldr + 0x10
    wstr = ldr + 0x400
    # Pre-create all entry slots so forward links resolve regardless of loop order.
    for i, (name, _, _) in enumerate(mods):
        entries[name] = ldr + 0x100 + 0x80 * i
    for i, (name, base, _) in enumerate(mods):
        e = entries[name]
        prev = head if i == 0 else entries[order[i - 1]]
        nxt = entries[order[i + 1]] if i + 1 < len(order) else head
        w = lambda a, d: uc.mem_write(a, d)          # noqa: E731
        w(e + 0x00, struct.pack("<Q", nxt))          # InLoadOrderLinks.flink
        w(e + 0x08, struct.pack("<Q", prev))         # .blink
        w(e + 0x10, struct.pack("<Q", e)); w(e + 0x18, struct.pack("<Q", e))
        w(e + 0x20, struct.pack("<Q", e)); w(e + 0x28, struct.pack("<Q", e))
        w(e + 0x30, struct.pack("<Q", base))         # DllBase
        w(e + 0x38, struct.pack("<Q", 0))            # EntryPoint
        w(e + 0x40, struct.pack("<I", IMG_SIZE))     # SizeOfImage
        full = f"C:\\Windows\\System32\\{name}".encode("utf-16le")
        bname = name.encode("utf-16le")
        # Real Windows UNICODE_STRING: len(2) + max(2) + 4B pad + ptr(8) —
        # BaseDllName.Buffer sits at entry+0x60, FullDllName.Buffer at +0x50.
        w(e + 0x48, struct.pack("<HH4xQ", len(full), len(full), wstr))
        w(e + 0x58, struct.pack("<HH4xQ", len(bname), len(bname),
                                wstr + len(full)))
        w(wstr, full)
        w(wstr + len(full), bname)
        wstr += 0x100
    w(head + 0x00, struct.pack("<Q", entries[order[0]]))   # head flink -> exe
    w(head + 0x08, struct.pack("<Q", entries[order[-1]]))  # head blink <- kernel32
    w(peb + 0x10, struct.pack("<Q", EXE_IMG))        # ImageBaseAddress
    w(peb + 0x18, struct.pack("<Q", ldr))            # Ldr
    w(teb + 0x60, struct.pack("<Q", peb))            # gs:[0x60] -> PEB
    return {"teb": teb, "peb": peb, "ldr": ldr, "head": head,
            "entries": entries, "bases": bases, "exports": exports}


def run_full_blob(blob: bytes, layer2_entry_off: int) -> dict:
    """Execute a full blob against the synthetic PEB/module/export environment.

    Returns a state dict with layer2_reached / abi / rax (the Layer-2 return
    value), alloc_calls / memmove_calls / vp_calls / lla_calls / gpa_calls,
    dllmain (first execution in the VirtualAlloc'd region + its rcx/rdx/r8),
    and a handle on the Uc instance for post-run memory assertions.
    """
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    blob_size = (len(blob) + 0xFFF) & ~0xFFF
    region = blob_size + 0x2000
    uc.mem_map(BLOB_BASE, region, perms=7)
    uc.mem_write(BLOB_BASE, blob)
    uc.mem_map(STACK_BASE, STACK_SIZE, perms=7)
    rsp = STACK_BASE + STACK_SIZE - 0x10
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.mem_write(rsp, struct.pack("<Q", EXIT_STUB))  # final `ret` target
    uc.mem_map(EXIT_STUB, 0x1000, perms=7)
    uc.mem_write(EXIT_STUB, b"\xEB\xFE")
    uc.mem_map(HEAP_BASE, HEAP_SIZE, perms=7)        # VirtualAlloc bump region
    sysinfo = install_system(uc)
    uc.msr_write(GS_BASE_MSR, sysinfo["teb"])        # gs:[0x60] now reads the PEB

    # ── dynamic-module + wildcard-stub region ──────────────────────────────
    # Real emitters load REAL DLLs whose imports reach beyond the synthetic
    # OS's three modules and six exports (GetModuleHandleA, CreateFileA, CRT
    # entries, …). Two fallbacks make any real import table resolvable:
    #  * LoadLibraryA of an unknown DLL → synthesize a module image on the
    #    fly (mem_map a 0x4000 region, return its base; its export table is
    #    never consulted because GetProcAddress below falls back too).
    #  * GetProcAddress of an unknown export → a per-name stub in the
    #    wildcard page holding `mov eax, 1; ret` (b8 01 00 00 00 c3), so the
    #    IAT slot is populated with a non-NULL, non-crashing body and the
    #    reflective load proceeds to DllMain. Real EDR-loading blobs would
    #    want these stubbed semantically; this fixture's DllMain ignores the
    #    return values, which is the contract being probed (loader plumbing,
    #    not API semantics).
    DYNM_BASE = 0x75_0000
    uc.mem_map(DYNM_BASE, 0x10000, perms=7)
    dynmod = {"next": DYNM_BASE}
    stub = {"next": DYNM_BASE + 0x8000, "seq": 0}

    state = {"layer2_reached": False, "alloc_calls": [], "memmove_calls": [],
             "vp_calls": [], "lla_calls": [], "gpa_calls": [], "dllmain": None,
             "wild_lla": [], "wild_gpa": []}
    entry_va = BLOB_BASE + layer2_entry_off
    alloc = {"next": HEAP_BASE}

    # ── fault recorder: capture (rip, kind, address) before the UcError ────
    from unicorn import (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                         UC_HOOK_MEM_FETCH_UNMAPPED)

    def on_fault(uc, access, address, size, value, ud):
        state.setdefault("faults", []).append(
            (uc.reg_read(UC_X86_REG_RIP), access, address, size))
        return False  # not handled → propagates as UcError → caught below

    for _t in (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
               UC_HOOK_MEM_FETCH_UNMAPPED):
        uc.hook_add(_t, on_fault)

    # ── blob-region hook: Layer-2 entry (with bridge-ABI adaptation) + exit ─
    def on_blob(uc, address, size, ud):
        if address == entry_va:
            if not state["layer2_reached"]:
                state["layer2_reached"] = True
                if uc.reg_read(UC_X86_REG_R9) == 0:
                    # Legacy handoff (no bridge in LAYER1 yet): rax=enc_len,
                    # rbx=&header, rsi=&nonce, rdi=&ct. Convert to the
                    # pic-loader ABI: rcx=&key (=rbx-0x20), rdx=&nonce,
                    # r8=&ct, r9=ct_len. No-op once the emitter's bridge
                    # (mov rcx,rbx; sub rcx,0x20; mov rdx,rsi; mov r8,rdi;
                    # mov r9,rax) is appended to LAYER1_BOOTSTRAP.
                    rax = uc.reg_read(UC_X86_REG_RAX)
                    rbx = uc.reg_read(UC_X86_REG_RBX)
                    uc.reg_write(UC_X86_REG_RCX, rbx - 0x20)
                    uc.reg_write(UC_X86_REG_RDX, uc.reg_read(UC_X86_REG_RSI))
                    uc.reg_write(UC_X86_REG_R8, uc.reg_read(UC_X86_REG_RDI))
                    uc.reg_write(UC_X86_REG_R9, rax)
                    state["abi"] = "legacy-converted"
                else:
                    state["abi"] = "bridge"
        elif address == EXIT_STUB:
            uc.emu_stop()
        elif address >= BLOB_BASE + region:
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, on_blob, None, BLOB_BASE, BLOB_BASE + region)

    # ── heap-region hook: first execution = DllMain entry (DllMain-call hook) ─
    def on_heap(uc, address, size, ud):
        if state["dllmain"] is None:
            state["dllmain"] = {
                "addr": address,
                "base": uc.reg_read(UC_X86_REG_RCX),
                "reason": uc.reg_read(UC_X86_REG_RDX),
                "reserved": uc.reg_read(UC_X86_REG_R8),
            }
    uc.hook_add(UC_HOOK_CODE, on_heap, None, HEAP_BASE, HEAP_BASE + HEAP_SIZE)

    def read_cstr(addr, cap=128):
        return uc.mem_read(addr, cap).split(b"\0")[0]

    # ── export-stub hooks (emulated implementations) ──────────────────────
    def on_va(uc, address, size, ud):
        size_ = uc.reg_read(UC_X86_REG_RDX)
        typ = uc.reg_read(UC_X86_REG_R8)
        prot = uc.reg_read(UC_X86_REG_R9)
        base = alloc["next"]
        aligned = (size_ + 0xFFF) & ~0xFFF
        if size_ and base + aligned <= HEAP_BASE + HEAP_SIZE:
            alloc["next"] = base + aligned
            state["alloc_calls"].append({"addr": uc.reg_read(UC_X86_REG_RCX),
                                         "size": size_, "type": typ,
                                         "prot": prot, "base": base})
            uc.reg_write(UC_X86_REG_RAX, base)
        else:
            state["alloc_calls"].append({"addr": uc.reg_read(UC_X86_REG_RCX),
                                         "size": size_, "type": typ,
                                         "prot": prot, "base": 0})
            uc.reg_write(UC_X86_REG_RAX, 0)

    def on_vp(uc, address, size, ud):
        old = uc.reg_read(UC_X86_REG_R9)
        if old:
            uc.mem_write(old, struct.pack("<I", 0x40))  # old protection
        state["vp_calls"].append({"addr": uc.reg_read(UC_X86_REG_RCX),
                                  "size": uc.reg_read(UC_X86_REG_RDX),
                                  "prot": uc.reg_read(UC_X86_REG_R8)})
        uc.reg_write(UC_X86_REG_RAX, 1)

    def on_rtlmm(uc, address, size, ud):
        dst = uc.reg_read(UC_X86_REG_RCX)
        src = uc.reg_read(UC_X86_REG_RDX)
        n = uc.reg_read(UC_X86_REG_R8)
        if n:
            # unicorn 2.x mem_read returns bytearray; mem_write wants bytes.
            uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        state["memmove_calls"].append({"dst": dst, "src": src, "len": n})
        uc.reg_write(UC_X86_REG_RAX, dst)

    def on_rtlzm(uc, address, size, ud):
        dst = uc.reg_read(UC_X86_REG_RCX)
        n = uc.reg_read(UC_X86_REG_RDX)
        if n:
            uc.mem_write(dst, b"\x00" * n)
        uc.reg_write(UC_X86_REG_RAX, dst)

    def on_lla(uc, address, size, ud):
        name = read_cstr(uc.reg_read(UC_X86_REG_RCX))
        state["lla_calls"].append(name)
        want = name.decode("ascii", "replace").lower()
        base = 0
        for mname, mbase in sysinfo["bases"].items():
            if mname == want or mname.split(".")[0] == want.split(".")[0]:
                base = mbase
                break
        if base == 0:
            # Unknown module (e.g. msvcrt.dll): synthesize an image region.
            base = dynmod["next"]
            dynmod["next"] += 0x4000
            state["wild_lla"].append(name)
        uc.reg_write(UC_X86_REG_RAX, base)

    def on_gpa(uc, address, size, ud):
        mod = uc.reg_read(UC_X86_REG_RCX)
        name = read_cstr(uc.reg_read(UC_X86_REG_RDX))
        state["gpa_calls"].append((mod, name))
        va = 0
        for mname, mbase in sysinfo["bases"].items():
            if mbase == mod:
                va = sysinfo["exports"][mname].get(name.decode("ascii", "replace"), 0)
                break
        if va == 0:
            # Unknown export: per-name `mov eax, 1; ret` stub.
            va = stub["next"]
            stub["next"] += 0x10
            uc.mem_write(va, b"\xB8\x01\x00\x00\x00\xC3")
            state["wild_gpa"].append(name)
        uc.reg_write(UC_X86_REG_RAX, va)

    def on_null(uc, address, size, ud):
        uc.reg_write(UC_X86_REG_RAX, 0)

    handlers = {
        "VirtualAlloc": on_va, "VirtualProtect": on_vp,
        "RtlMoveMemory": on_rtlmm, "RtlZeroMemory": on_rtlzm,
        "LoadLibraryA": on_lla, "GetProcAddress": on_gpa,
    }
    for exps in sysinfo["exports"].values():
        for expname, va in exps.items():
            uc.hook_add(UC_HOOK_CODE, handlers.get(expname, on_null), None, va, va + 1)

    try:
        uc.emu_start(BLOB_BASE, BLOB_BASE + region, count=10_000_000)
    except Exception as e:  # noqa: BLE001 — surface emulation faults
        state["fault"] = f"{type(e).__name__}: {e}"
    state["rip"] = uc.reg_read(UC_X86_REG_RIP)
    state["rax"] = uc.reg_read(UC_X86_REG_RAX)   # Layer-2 return value
    state["uc"] = uc
    return state


def check(state: dict, label: str, cond: bool) -> bool:
    print(f"  {'ok ' if cond else 'FAIL'} {label}")
    return cond


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Headless Nyx loader probe (Unicorn, real Layer-1 bytes)")
    ap.add_argument("--blob", metavar="PATH",
                    help="run the full-blob probe against a real emitter blob "
                         "(definitive layout: [LAYER1(+bridge)][key 32][NYX2 "
                         "header][ct||tag][LAYER2])")
    ap.add_argument("--fixture", metavar="PATH",
                    help="use an external PE32+ file as the synthetic full-blob "
                         "fixture instead of the built-in one")
    args = ap.parse_args(argv)
    ok = True

    # ── Test 1: magic present ─────────────────────────────────────────────
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

    # ── Test 2: magic absent ──────────────────────────────────────────────
    s = run_probe(build_blob(with_magic=False))
    print(f"[probe] magic-absent: rip=0x{s['rip'] - BLOB_BASE:02x} "
          f"bail_ret={s['bail_ret_seen']} layer2={s['layer2_reached']}")
    if s["layer2_reached"] or not s["bail_ret_seen"]:
        print(f"  FAIL: expected bail ret at 0x26 (layer2={s['layer2_reached']}, "
              f"bail={s['bail_ret_seen']})")
        ok = False
        if "fault" in s:
            print(f"  note: emulator fault: {s['fault']}")
            for _f in s.get("faults", [])[:4]:
                print(f"  note:   at rip=0x{_f[0]:x} kind={_f[1]} addr=0x{_f[2]:x} size={_f[3]}")
            ok = False

    # ── Test 3: synthetic full blob (always) ──────────────────────────────
    fixture = build_fixture_pe() if not args.fixture else Path(args.fixture).read_bytes()
    try:
        entry_rva = pe_entry_rva(fixture)
    except ValueError as e:
        print(f"[full-blob] synthetic fixture invalid: {e}")
        ok = False
        fixture = None
    if fixture is not None:
        blob, info = build_full_blob(fixture)
        s = run_full_blob(blob, info["layer2_off"])
        alloc_base = s["alloc_calls"][0]["base"] if s["alloc_calls"] else None
        print(f"[full-blob] synthetic: layer2={s['layer2_reached']} "
              f"abi={s.get('abi')} ret=0x{s['rax']:x} dllmain={s['dllmain'] is not None} "
              f"alloc={[hex(c['size']) for c in s['alloc_calls']]}")
        checks = [
            ("Layer-2 entry reached", s["layer2_reached"] is True),
            ("Layer-2 returned 0", s.get("rax") == 0),
            ("no emulation fault", "fault" not in s),
            ("PEB-walk ABI adapted (bridge or legacy)", s.get("abi") in ("bridge", "legacy-converted")),
            ("DllMain-call hook fired", s.get("dllmain") is not None),
            ("VirtualAlloc size == ct_len", bool(s["alloc_calls"])
             and s["alloc_calls"][0]["size"] == len(fixture)),
            ("VirtualAlloc type == MEM_COMMIT|MEM_RESERVE", bool(s["alloc_calls"])
             and s["alloc_calls"][0]["type"] == 0x3000),
            ("VirtualAlloc prot == PAGE_EXECUTE_READWRITE", bool(s["alloc_calls"])
             and s["alloc_calls"][0]["prot"] == 0x40),
            ("RtlMoveMemory copied ct_len bytes", bool(s["memmove_calls"])
             and s["memmove_calls"][0]["len"] == len(fixture)),
            ("VirtualProtect called (RWX)", bool(s["vp_calls"])
             and s["vp_calls"][0]["prot"] == 0x40),
            ("decrypt+map round-trips to the fixture PE", alloc_base is not None
             and s["uc"].mem_read(alloc_base, len(fixture)) == fixture),
        ]
        if s.get("dllmain") is not None and alloc_base is not None:
            d = s["dllmain"]
            checks += [
                ("DllMain reason == DLL_PROCESS_ATTACH", d["reason"] == 1),
                ("DllMain reserved == NULL", d["reserved"] == 0),
                ("DllMain base == VirtualAlloc'd image", d["base"] == alloc_base),
                ("DllMain fired at the PE entry point", d["addr"] == alloc_base + entry_rva),
            ]
        for label, cond in checks:
            if not check(s, label, cond):
                ok = False
        if "fault" in s:
            print(f"  note: emulator fault: {s['fault']}")
            for _f in s.get("faults", [])[:4]:
                print(f"  note:   at rip=0x{_f[0]:x} kind={_f[1]} addr=0x{_f[2]:x} size={_f[3]}")
        if s["dllmain"] is None and s.get("abi") and s["layer2_reached"] and s.get("rax") != 0:
            print(f"  note: Layer-2 bailed with 0x{s['rax']:x} "
                  f"({'legacy-converted' if s.get('abi') == 'legacy-converted' else 'bridge'} ABI)")

    # ── Test 4: real emitter blob (--blob) ────────────────────────────────
    if args.blob:
        blob = Path(args.blob).read_bytes()
        try:
            layout = parse_full_blob_layout(blob)
        except ValueError as e:
            print(f"[full-blob] real blob layout check FAILED: {e}")
            ok = False
        else:
            s = run_full_blob(blob, layout["layer2_off"])
            print(f"[full-blob] real blob: layer2={s['layer2_reached']} "
                  f"abi={s.get('abi')} ret=0x{s['rax']:x} "
                  f"dllmain={s['dllmain'] is not None} "
                  f"alloc_calls={len(s['alloc_calls'])} "
                  f"lla_calls={len(s['lla_calls'])} gpa_calls={len(s['gpa_calls'])}")
            checks = [
                ("layout: NYX2 header after LAYER1+key, jmp lands on Layer-2",
                 True),  # parse_full_blob_layout raised otherwise
                ("Layer-2 entry reached", s["layer2_reached"] is True),
                ("Layer-2 returned 0", s.get("rax") == 0),
                ("no emulation fault", "fault" not in s),
                ("DllMain-call hook fired", s.get("dllmain") is not None),
                ("VirtualAlloc type == MEM_COMMIT|MEM_RESERVE", bool(s["alloc_calls"])
                 and s["alloc_calls"][0]["type"] == 0x3000),
                ("VirtualAlloc prot == PAGE_EXECUTE_READWRITE", bool(s["alloc_calls"])
                 and s["alloc_calls"][0]["prot"] == 0x40),
            ]
            for label, cond in checks:
                if not check(s, label, cond):
                    ok = False
            if "fault" in s:
                print(f"  note: emulator fault: {s['fault']}")
                for _f in s.get("faults", [])[:4]:
                    print(f"  note:   at rip=0x{_f[0]:x} kind={_f[1]} addr=0x{_f[2]:x} size={_f[3]}")

    print("loader-emu:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
