/* Ordinal-forwarding fixture host.
 *
 * Loads the deployed proxy (orddll.dll, original name) and resolves ordinal 1
 * via GetProcAddress. The loader must follow the proxy's NONAME forwarder to
 * orddll_orig.#1. Exit 0 iff the call returns 42.
 *
 * Dynamic resolution is deliberate: this stage isolates loader forwarder
 * semantics (the WP-H leftover "ordinal-only 转发运行时行为未实测"), not
 * import-table sideload mechanics — those are covered by host_version.c.
 *
 * Build (mingw):  x86_64-w64-mingw32-gcc -O2 host_ord.c -o host_ord.exe
 * Exit: 0 = ordinal call returned 42; 2 = load failed; 3 = resolve failed;
 *       4 = wrong return value.
 */
#include <windows.h>
#include <stdio.h>

typedef int(__stdcall *OrdAnswerFn)(void);

int main(void) {
    HMODULE h = LoadLibraryW(L"orddll.dll");
    if (!h) {
        printf("host_ord: LoadLibraryW failed (gle=%lu)\n", (unsigned long)GetLastError());
        return 2;
    }
    FARPROC p = GetProcAddress(h, (LPCSTR)MAKEINTRESOURCEA(1));
    if (!p) {
        printf("host_ord: GetProcAddress(#1) failed (gle=%lu)\n", (unsigned long)GetLastError());
        return 3;
    }
    int v = ((OrdAnswerFn)p)();
    printf("host_ord: ordinal #1 -> %d\n", v);
    fflush(stdout);
    Sleep(4000); /* let the proxy trigger thread load the fixture implant */
    return v == 42 ? 0 : 4;
}
