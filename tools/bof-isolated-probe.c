// bof-isolated-probe — real Win32 execution of nyx_selftest_bof_isolated
// under wine (or a real Windows host).
//
// Mirrors the loader-probe-exe philosophy: plain console process, no
// rundll32 (which hangs in non-interactive session 0 / wine), no window
// station APIs. Loads the selftest DLL and calls the export directly; the
// selftest ends the process via ExitProcess(bitmask), so the probe's exit
// code IS the selftest mask (expect 7 = 0b0111 on a healthy host).
//
// Exit codes: selftest mask (7 = pass) on success; 0xE0 = LoadLibrary
// failed; 0xE1 = export missing; 0xE2 = export returned (should never
// happen — selftest diverges).
//
// Build (mingw):
//   x86_64-w64-mingw32-gcc -O2 -o bof-isolated-probe.exe \
//     tools/bof-isolated-probe.c -lkernel32
//
// Run under wine:
//   wine64 bof-isolated-probe.exe <path-to-nyx_implant_win.dll>
//   echo $?   # expect 7

#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <nyx_implant_win.dll> [export]\n", argv[0]);
        return 0xE3;
    }
    const char *export = (argc >= 3) ? argv[2] : "nyx_selftest_bof_isolated";
    HMODULE h = LoadLibraryA(argv[1]);
    if (!h) {
        fprintf(stderr, "LoadLibraryA failed: %lu\n", (unsigned long)GetLastError());
        return 0xE0;
    }
    FARPROC p = GetProcAddress(h, export);
    if (!p) {
        fprintf(stderr, "GetProcAddress(%s) failed\n", export);
        return 0xE1;
    }
    /* The selftest diverges via ExitProcess(mask); never returns here. */
    ((void (__cdecl *)(void))p)();
    fprintf(stderr, "selftest returned unexpectedly\n");
    return 0xE2;
}
