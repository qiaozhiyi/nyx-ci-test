"""Minimal keystone stub for headless Qiling runs (tools/selftest-qiling).

qiling 1.4.6 imports keystone at module load (for its assembler), but
keystone-engine 0.9.2 has no py3.11/arm64 wheel and its source-built dylib
fails to load via ctypes on macOS arm64. The headless selftest runner never
assembles (load DLL -> run export -> read ExitProcess code), so a stub that
satisfies the imports is sufficient. Installed by the CI step as
<venv>/lib/python3.11/site-packages/keystone/__init__.py.

Values mirror keystone-engine 0.9.2's public constants; they are never
meaningfully used in this flow.
"""


class Ks:  # noqa: N801 — keystone's public class name
    def __init__(self, *args, **kwargs):
        pass

    def asm(self, *args, **kwargs):
        raise NotImplementedError(
            "keystone is stubbed in headless selftests; assembly is not used"
        )


def ks_version():
    return (0, 0)


def ks_arch_supported(*_args, **_kwargs):
    return False


KS_ARCH_ARM = 1
KS_ARCH_ARM64 = 2
KS_ARCH_MIPS = 3
KS_ARCH_X86 = 4
KS_ARCH_PPC = 5
KS_ARCH_SPARC = 6
KS_ARCH_SYSTEMZ = 7
KS_ARCH_HEXAGON = 8
KS_ARCH_EVM = 9
KS_ARCH_RISCV = 10

KS_MODE_LITTLE_ENDIAN = 0
KS_MODE_BIG_ENDIAN = 1 << 30
KS_MODE_ARM = 1 << 0
KS_MODE_THUMB = 1 << 4
KS_MODE_16 = 1 << 1
KS_MODE_32 = 1 << 2
KS_MODE_64 = 1 << 3
KS_MODE_MIPS32 = 1 << 2
KS_MODE_MIPS64 = 1 << 3
KS_MODE_PPC32 = 1 << 2
KS_MODE_PPC64 = 1 << 3
KS_MODE_SPARC32 = 1 << 2
KS_MODE_SPARC64 = 1 << 3
KS_MODE_RISCV32 = 1 << 2
KS_MODE_RISCV64 = 1 << 3
