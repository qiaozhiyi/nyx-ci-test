#!/usr/bin/env python3
"""Qiling feasibility runner for the implant selftest DLL.

Loads `nyx_implant_win.dll` (Windows x86_64 selftest build) under Qiling and
calls each `nyx_selftest_*` export in turn. Every selftest export terminates
the guest process through `ExitProcess(bitmask)`; the runner captures that
exit code (rcx at the ExitProcess hook) and reports a feasibility matrix.

The implant resolves Windows APIs itself through a PEB-walk + export-table
hash lookup (crates/implant-core/src/resolve.rs) and calls export addresses
directly — it does NOT use the IAT. Qiling intercepts those direct calls with
its per-instruction code hook and dispatches to its Python API
implementations by export name, so the rootfs only needs PE stubs whose
export tables carry the names the selftests resolve:

  kernel32.dll : ExitProcess, GetEnvironmentStringsW, FreeEnvironmentStringsW,
                 GetEnvironmentVariableW, GetComputerNameW,
                 GetCurrentProcessId, GetSystemTimeAsFileTime, LoadLibraryA
  ntdll.dll    : RtlCreateHeap, RtlAllocateHeap, memcpy, memset, memcmp,
                 strlen (implant heap allocator + mingw CRT mem calls)
  advapi32.dll : GetUserNameW                    (hostinfo username probe)

The api-ms-win-crt-* IAT entries in the DLL are redirected by Qiling to
ntdll.dll (its api-set fallback key DLL), so the mem functions above must
live there. memcpy is serviced by Qiling's own hook_memcpy; the APIs Qiling
has no implementation for are serviced by overrides registered below (see
setup_overrides): RtlCreateHeap (dummy handle; qiling's RtlAllocateHeap
ignores the handle), GetEnvironmentStringsW (a populated env block so the
env dump-all sub-check sees a non-empty result), GetUserNameW (writes
"qiling" so the hostinfo username sub-check passes), and memset/memcmp/
strlen (byte-level ops for the allocator and string paths).

CRT imports the ntdll stub does NOT export (wcslen, strncmp, calloc, free,
the CRT-startup helpers, ...) are left by Qiling pointing at unmapped magic
stub addresses, so any IAT call to them dies with UC_ERR_FETCH_UNMAPPED.
Newer nightly/LLVM makes this bite: it recognizes the u16 length loop in
do_env_dump_all (implant-tasks/src/recon.rs) and emits a real `wcslen`
call through the IAT, crashing nyx_selftest_env. fixup_crt_iat() redirects
every unresolved IAT slot to a mapped shim page implemented in Python below
(wcslen/strncmp get faithful semantics; the never-called CRT-startup helpers
get a return-0 stub, strictly better than the previous crash).

Exit codes:
  bitmask   -> sub-check bits set (see crates/implant-tasks/src/selftests.rs)
  0xAD      -> allocator OOM (fallback bump buffer exhausted)
  0xFFFFFFFE-> runtime bootstrap failed (not used by the matrix below)
"""

import argparse
import json
import sys
import time
from pathlib import Path

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from unicorn import UcError

from make_rootfs import ensure_rootfs

HERE = Path(__file__).resolve().parent
ROOTFS = HERE / "rootfs"
DLL = (
    HERE.parent.parent
    / "crates"
    / "implant-win"
    / "target"
    / "x86_64-pc-windows-gnu"
    / "release"
    / "nyx_implant_win.dll"
)

# Qiling's RegistryManager refuses to start without a hive directory; the
# selftests never touch the registry, so synthesize valid empty hives once.
ensure_rootfs(ROOTFS)

# (export name, one-line note) in run order.
MATRIX = [
    ("nyx_selftest_calib42", "calibration: exit 42, no syscalls"),
    ("nyx_selftest_env", "env dump-all + unset-var via kernel32"),
    ("nyx_selftest_config", "in-memory config blob decode (pure)"),
    ("nyx_selftest_hostinfo", "hostname/user/pid/beacon_id via PEB walk"),
    ("nyx_selftest_task_guard", "VEH task guard: rootfs lacks VEH/capture exports → env-skip flag (exit 9)"),
    ("nyx_selftest_bof_isolated", "B3 isolated BOF: stub kernel32 lacks CreateProcessW → env-skip flag (exit 9)"),
]

# Per-export emulation budget (seconds). A selftest that hangs (e.g. an
# unimplemented API falling through to real code) is killed by the timeout.
RUN_TIMEOUT_MS = 20_000


def find_export(ql: Qiling, name: str):
    """Locate an export of the main image by name.

    The main image's exports are registered in `ql.loader.export_symbols`
    (address -> {name, ordinal}); every loaded DLL's exports land in
    `ql.loader.import_symbols` (address -> {name, dll, ordinal}).
    """
    for addr, sym in ql.loader.export_symbols.items():
        if sym.get("name") == name.encode():
            return addr
    for addr, sym in ql.loader.import_symbols.items():
        if sym.get("name") == name.encode():
            return addr
    return None


def _skip_stub_body(ql: Qiling) -> None:
    """Return from the (never-executed) stub function to its caller.

    Qiling's hook_winapi fires at the export address before the stub body
    runs, and the stub body would clobber the return value we wrote into rax.
    Mirror what qiling's own os.call does for decorated hooks: advance pc to
    the return address on the stack and pop it.
    """
    rsp = ql.arch.regs.read("rsp")
    retaddr = ql.mem.read_ptr(rsp)
    ql.arch.regs.write("rsp", rsp + 8)
    ql.arch.regs.arch_pc = retaddr


def setup_overrides(ql: Qiling) -> None:
    """Register Python implementations for APIs the stubs expose but qiling
    does not implement. Handlers are invoked as api_func(ql, address, name)
    with no argument parsing, so they read guest state directly and must set
    the return value (rax) themselves.
    """

    def hook_RtlCreateHeap(ql: Qiling, address: int, name: str) -> None:
        # qiling's hook_RtlAllocateHeap ignores the heap handle, so any
        # non-null value satisfies the implant's ensure_heap().
        ql.arch.regs.write("rax", 0x1000)
        _skip_stub_body(ql)

    def hook_GetEnvironmentStringsW(ql: Qiling, address: int, name: str) -> None:
        # A real (non-empty) env block so do_env("") yields Output(non-empty).
        block = "QILING_TEST=1\x00\x00".encode("utf-16le")
        buf = ql.os.heap.alloc(len(block))
        ql.mem.write(buf, block)
        ql.arch.regs.write("rax", buf)
        _skip_stub_body(ql)

    def hook_GetUserNameW(ql: Qiling, address: int, name: str) -> None:
        # GetUserNameW(lpBuffer=rcx, lpnSize=rdx): write "qiling" and set the
        # size so hostinfo::username() != "user".
        lp_buffer = ql.arch.regs.read("rcx")
        lpn_size = ql.arch.regs.read("rdx")
        user = "qiling\x00".encode("utf-16le")
        ql.mem.write(lp_buffer, user)
        ql.mem.write_ptr(lpn_size, len(user), 4)
        ql.arch.regs.write("rax", 1)
        _skip_stub_body(ql)

    def hook_memset(ql: Qiling, address: int, name: str) -> None:
        # memset(dest=rcx, val=rdx, count=r8); rax = dest
        dest, val, count = (
            ql.arch.regs.read("rcx"),
            ql.arch.regs.read("rdx"),
            ql.arch.regs.read("r8"),
        )
        if count:
            ql.mem.write(dest, bytes([val & 0xFF]) * count)
        ql.arch.regs.write("rax", dest)
        _skip_stub_body(ql)

    def hook_memcmp(ql: Qiling, address: int, name: str) -> None:
        # memcmp(a=rcx, b=rdx, count=r8); rax = 0 / negative / positive
        a, b, count = (
            ql.arch.regs.read("rcx"),
            ql.arch.regs.read("rdx"),
            ql.arch.regs.read("r8"),
        )
        res = 0
        if count:
            ba = ql.mem.read(a, count)
            bb = ql.mem.read(b, count)
            if ba < bb:
                res = -1
            elif ba > bb:
                res = 1
        ql.arch.regs.write("rax", res & 0xFFFFFFFFFFFFFFFF)
        _skip_stub_body(ql)

    def hook_strlen(ql: Qiling, address: int, name: str) -> None:
        # strlen(s=rcx); rax = length
        s = ql.arch.regs.read("rcx")
        n = 0
        while ql.mem.read(s + n, 1) != b"\x00":
            n += 1
            if n > 1 << 20:  # runaway guard
                break
        ql.arch.regs.write("rax", n)
        _skip_stub_body(ql)

    ql.os.set_api("RtlCreateHeap", hook_RtlCreateHeap, QL_INTERCEPT.CALL)
    ql.os.set_api("GetEnvironmentStringsW", hook_GetEnvironmentStringsW, QL_INTERCEPT.CALL)
    ql.os.set_api("GetUserNameW", hook_GetUserNameW, QL_INTERCEPT.CALL)
    ql.os.set_api("memset", hook_memset, QL_INTERCEPT.CALL)
    ql.os.set_api("memcmp", hook_memcmp, QL_INTERCEPT.CALL)
    ql.os.set_api("strlen", hook_strlen, QL_INTERCEPT.CALL)


def fixup_crt_iat(ql: Qiling, dll_path: Path) -> list:
    """Redirect IAT slots Qiling left pointing at unmapped memory.

    Qiling resolves the DLL's api-ms-win-crt-* imports against the ntdll stub
    (its api-set fallback). Names the stub does not export (wcslen, strncmp,
    calloc, free, CRT-startup helpers) get a magic stub address that is not
    backed by any mapping, so calling it raises UC_ERR_FETCH_UNMAPPED. Newer
    nightly/LLVM emits exactly such a call: loop-idiom recognition turns the
    u16 length loop in do_env_dump_all into `wcslen`.

    For every import slot whose target is unmapped, patch the slot to a byte
    in a freshly mapped shim page (a bare `ret`) and register a hook_address
    callback that computes the return value in Python before the `ret` runs.
    wcslen/strncmp get real implementations (they ARE called by the current
    codegen); everything else gets a return-0 stub — never called by the
    selftests, and strictly better than the previous hard crash.

    Returns the list of (dll, name) pairs that were redirected.
    """
    import pefile  # qiling dependency; deferred so --help stays cheap

    def shim_wcslen(ql: Qiling) -> None:
        # wcslen(s=rcx); rax = number of u16 code units before the NUL
        s = ql.arch.regs.read("rcx")
        n = 0
        while ql.mem.read(s + n * 2, 2) != b"\x00\x00":
            n += 1
            if n > 1 << 20:  # runaway guard
                break
        ql.arch.regs.write("rax", n)

    def shim_strncmp(ql: Qiling) -> None:
        # strncmp(a=rcx, b=rdx, count=r8); rax = 0 / negative / positive
        a, b, count = (
            ql.arch.regs.read("rcx"),
            ql.arch.regs.read("rdx"),
            ql.arch.regs.read("r8"),
        )
        res = 0
        for i in range(count):
            ca = ql.mem.read(a + i, 1)[0]
            cb = ql.mem.read(b + i, 1)[0]
            if ca != cb:
                res = ca - cb
                break
            if ca == 0:
                break
        ql.arch.regs.write("rax", res & 0xFFFFFFFFFFFFFFFF)

    def shim_ret0(ql: Qiling) -> None:
        ql.arch.regs.write("rax", 0)

    shims = {"wcslen": shim_wcslen, "strncmp": shim_strncmp}

    pe = pefile.PE(str(dll_path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return []

    main_base = None
    dll_name = dll_path.name.lower()
    for img in ql.loader.images:
        if img.path.replace("\\", "/").rsplit("/", 1)[-1].lower() == dll_name:
            main_base = img.base
            break
    if main_base is None:
        return []
    pe_base = pe.OPTIONAL_HEADER.ImageBase

    def is_mapped(addr: int) -> bool:
        return any(start <= addr < end for start, end, *_ in ql.mem.map_info)

    # Lazily map one page of `ret` stubs; each redirect gets its own 16-byte
    # slot so hook_address can attach a per-function callback.
    shim_page = None
    shim_next = 0

    def next_shim_addr() -> int:
        nonlocal shim_page, shim_next
        if shim_page is None or shim_next + 0x10 > 0x1000:
            cand = 0x40000000
            while is_mapped(cand):
                cand += 0x1000
            ql.mem.map(cand, 0x1000, info="crt-iat-shims")
            ql.mem.write(cand, b"\xc3" * 0x1000)  # every byte a `ret`
            shim_page, shim_next = cand, 0
        addr = shim_page + shim_next
        shim_next += 0x10
        return addr

    redirected = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            slot = main_base + (imp.address - pe_base)
            target = ql.mem.read_ptr(slot)
            if is_mapped(target):
                continue
            name = imp.name.decode(errors="replace") if imp.name else f"ord{imp.ordinal}"
            addr = next_shim_addr()
            ql.mem.write_ptr(slot, addr)
            ql.hook_address(shims.get(name, shim_ret0), addr)
            redirected.append((dll, name))
    return redirected


def run_export(dll_path: Path, export: str, timeout_ms: int) -> dict:
    """Load the DLL fresh and invoke one selftest export.

    Returns {exit_code, verdict, detail}. The selftest calls
    ExitProcess(code); qiling's hook_ExitProcess stops emulation and leaves
    the code in rcx, which we read back after emu_start returns.
    """
    result = {"exit_code": None, "verdict": "FAIL", "detail": ""}
    ql = None
    try:
        ql = Qiling(
            [str(dll_path)],
            str(ROOTFS),
            verbose=QL_VERBOSE.OFF,
            console=False,
            libcache=False,
        )
        setup_overrides(ql)
        fixup_crt_iat(ql, dll_path)

        addr = find_export(ql, export)
        if addr is None:
            result["detail"] = f"export {export} not found in loaded image"
            return result

        # Stage a call frame: entry rsp must be 16-aligned minus one slot
        # (the return address), as if the export had been `call`ed. A sentinel
        # return address of 0 turns an unexpected normal return into a
        # catchable fault instead of silent garbage execution.
        rsp = ql.arch.regs.read("rsp")
        rsp = (rsp & ~0xF) - 8
        ql.mem.write_ptr(rsp, 0)
        ql.arch.regs.write("rsp", rsp)

        t0 = time.monotonic()
        # unicorn emu_start timeout is in MICROseconds (see qiling core.emu_start
        # docstring); 2.x returns normally on timeout rather than raising.
        ql.uc.emu_start(addr, 0, timeout_ms * 1000)
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms >= timeout_ms - 100:
            result["detail"] = f"emulation timeout after {timeout_ms} ms"
            return result
        # ExitProcess hook stopped emulation; uExitCode is still in rcx.
        result["exit_code"] = ql.arch.regs.read("rcx")
        result["verdict"] = "PASS"
        return result
    except UcError as ex:
        result["detail"] = f"UcError {ex.errno} ({ex})"
        return result
    except Exception as ex:  # QlErrorSyscallError / internal faults
        result["detail"] = f"{type(ex).__name__}: {ex}"
        return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dll", type=Path, default=DLL, help="path to nyx_implant_win.dll")
    ap.add_argument("--json", action="store_true", help="emit the matrix as JSON")
    ap.add_argument("--timeout-ms", type=int, default=RUN_TIMEOUT_MS)
    args = ap.parse_args()

    if not args.dll.exists():
        print(f"error: DLL not found: {args.dll}", file=sys.stderr)
        return 2

    rows = []
    for export, note in MATRIX:
        r = run_export(args.dll, export, args.timeout_ms)
        rows.append(
            {
                "export": export,
                "works": r["verdict"] == "PASS",
                "exit_code": r["exit_code"],
                "detail": r["detail"],
                "note": note,
            }
        )

    n_ok = sum(1 for r in rows if r["works"])
    if args.json:
        print(json.dumps({"exports_tested": len(rows), "exports_working": n_ok, "matrix": rows}, indent=2))
    else:
        print("selftest export feasibility matrix (Qiling x86_64 windows)")
        print(f"{'export':<32} {'works':<6} {'exit':<10} note")
        for r in rows:
            exit_s = "n/a" if r["exit_code"] is None else f"0x{r['exit_code']:x}"
            extra = f" | {r['detail']}" if (not r["works"] and r["detail"]) else ""
            print(f"{r['export']:<32} {str(r['works']):<6} {exit_s:<10} {r['note']}{extra}")
        print(f"\n{len(rows)} exports tested, {n_ok} working (threshold: >=3)")

    return 0 if n_ok >= 3 else 1


if __name__ == "__main__":
    sys.exit(main())
