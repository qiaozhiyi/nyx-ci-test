#!/usr/bin/env python3
"""Generate the minimal Qiling Windows rootfs for the selftest runner.

Qiling's Windows OS layer demands a registry hive directory
(<rootfs>/Windows/registry) containing real REGF hive files before it will
construct an emulator instance. The selftest matrix never reads the registry
(env/config/hostinfo/calib42 all resolve APIs through the PEB walk), so we
generate minimal but VALID empty hives (validated against python-registry,
the same parser Qiling uses) instead of shipping binary blobs in git.

Also regenerates the PE stub DLLs if mingw is available and the stubs are
newer than the DLLs; the stubs are checked in, so this is optional.

Usage: python3 make_rootfs.py [rootfs_dir]
"""

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ROOTFS = HERE / "rootfs"

HIVE_NAMES = ["SECURITY", "SAM", "SOFTWARE", "SYSTEM", "HARDWARE", "NTUSER.DAT"]

STUB_DLLS = [
    ("kernel32.dll", "kernel32_stub.c"),
    ("ntdll.dll", "ntdll_stub.c"),
    ("advapi32.dll", "advapi32_stub.c"),
]


def make_hive(name: str) -> bytes:
    """Build a minimal single-bin REGF hive with an empty root key.

    Layout follows the public REGF format (libregf/python-registry):
    a 0x1000 base block + one 0x1000 hbin whose first cell is the root nk.
    Validated in CI by python-registry (the parser Qiling's RegistryManager
    uses) — see the check in runner.py.
    """
    bin_size = 0x1000

    bb = bytearray(0x1000)
    bb[0:4] = b"regf"
    struct.pack_into("<I", bb, 0x04, 1)  # primary sequence number
    struct.pack_into("<I", bb, 0x08, 1)  # secondary sequence number
    struct.pack_into("<Q", bb, 0x0C, 0x01D4000000000000)  # FILETIME ~2000
    struct.pack_into("<I", bb, 0x14, 1)  # major version
    struct.pack_into("<I", bb, 0x18, 3)  # minor version
    struct.pack_into("<I", bb, 0x1C, 0)  # file type: primary
    struct.pack_into("<I", bb, 0x20, 1)  # format: 1
    struct.pack_into("<I", bb, 0x24, 0x18)  # root cell offset (rel. first hbin)
    struct.pack_into("<I", bb, 0x28, bin_size)  # hive bins data size
    struct.pack_into("<I", bb, 0x2C, 1)  # clustering factor
    bb[0x30 : 0x30 + 64] = name.encode("utf-16le")[:64].ljust(64, b"\x00")
    # checksum = sum of the u32 words of [0x00, 0x1FC)
    ck = sum(struct.unpack_from("<I", bb, o)[0] for o in range(0, 0x1FC, 4)) & 0xFFFFFFFF
    struct.pack_into("<I", bb, 0x1FC, ck)

    hb = bytearray(bin_size)
    hb[0:4] = b"hbin"
    struct.pack_into("<i", hb, 0x04, 0)  # offset from first hbin
    struct.pack_into("<I", hb, 0x08, bin_size)
    struct.pack_into("<Q", hb, 0x10, 0x01D4000000000000)

    # Root key cell: header (i32 size) at bin offset 0x18, nk record after it.
    nk = bytearray(0x50)
    struct.pack_into("<i", nk, 0x00, -0x50)  # allocated, cell size 0x50
    nk[4:6] = b"nk"
    struct.pack_into("<H", nk, 0x06, 0x2C)  # flags: root key
    struct.pack_into("<Q", nk, 0x08, 0x01D4000000000000)
    struct.pack_into("<I", nk, 0x10, 0x001F)  # access bits
    struct.pack_into("<I", nk, 0x14, 0xFFFFFFFF)  # parent (root)
    struct.pack_into("<I", nk, 0x18, 0)  # subkeys
    struct.pack_into("<I", nk, 0x1C, 0)
    struct.pack_into("<I", nk, 0x20, 0xFFFFFFFF)  # subkey list offset
    struct.pack_into("<I", nk, 0x24, 0xFFFFFFFF)
    struct.pack_into("<I", nk, 0x28, 0)  # values
    struct.pack_into("<I", nk, 0x2C, 0xFFFFFFFF)  # value list offset
    struct.pack_into("<I", nk, 0x30, 0xFFFFFFFF)  # security offset
    struct.pack_into("<I", nk, 0x34, 0xFFFFFFFF)  # class offset
    struct.pack_into("<I", nk, 0x38, 0)
    struct.pack_into("<I", nk, 0x3C, 0)
    struct.pack_into("<I", nk, 0x40, 0)
    struct.pack_into("<I", nk, 0x44, 0)
    struct.pack_into("<I", nk, 0x48, 0)  # workvar
    struct.pack_into("<H", nk, 0x4C, 0)  # key name length
    struct.pack_into("<H", nk, 0x4E, 0)  # class name length
    hb[0x18 : 0x18 + 0x50] = nk
    # free cell marking the remainder of the bin
    struct.pack_into("<i", hb, 0x18 + 0x50, 0x1000 - 0x18 - 0x50)

    return bytes(bb) + bytes(hb)


def ensure_rootfs(rootfs: Path) -> None:
    regdir = rootfs / "Windows" / "registry"
    regdir.mkdir(parents=True, exist_ok=True)
    for name in HIVE_NAMES:
        target = regdir / name
        if not target.exists():
            target.write_bytes(make_hive(name))
            print(f"wrote {target.relative_to(rootfs)}")


def rebuild_stubs(rootfs: Path) -> None:
    """Rebuild the PE stub DLLs from the C sources in stubs/ (needs mingw).

    The checked-in DLLs are the CI source of truth; this is for regenerating
    them after a stub change. Uses x86_64-w64-mingw32-gcc from PATH.
    """
    gcc = shutil.which("x86_64-w64-mingw32-gcc")
    if gcc is None:
        print("x86_64-w64-mingw32-gcc not found; stub DLLs left unchanged")
        return 1
    sysdir = rootfs / "windows" / "system32"
    sysdir.mkdir(parents=True, exist_ok=True)
    for dll, src in STUB_DLLS:
        src_path = HERE / "stubs" / src
        out = sysdir / dll
        subprocess.run([gcc, "-shared", "-O1", "-o", str(out), str(src_path)], check=True)
        print(f"rebuilt {out.relative_to(rootfs)}")
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    rootfs = Path(args[0]) if args else DEFAULT_ROOTFS
    ensure_rootfs(rootfs)
    if "--stubs" in sys.argv:
        return rebuild_stubs(rootfs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
