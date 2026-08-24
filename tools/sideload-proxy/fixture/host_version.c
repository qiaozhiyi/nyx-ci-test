/* Sideload-chain fixture host (named-export stage).
 *
 * Statically imports version.dll and calls GetFileVersionInfoSizeW — with the
 * proxy deployed as version.dll, this call must resolve through the proxy's
 * linker forwarder to version_orig.dll and return a real value. Proves the
 * WP-H chain end-to-end on the real Windows loader: app-dir search order →
 * proxy load → named-export forwarding.
 *
 * Then waits: the proxy's DllMain trigger thread (delay, then LoadLibraryW of
 * the staged implant fixture) fires while we sleep — exiting early would kill
 * the thread before the marker lands. Marker presence is asserted by the
 * harness, not here.
 *
 * Build (mingw):  x86_64-w64-mingw32-gcc -O2 host_version.c -o host_version.exe -lversion
 * Exit: 0 = forwarded call returned nonzero size; 1 = call failed.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(L"C:\\Windows\\System32\\kernel32.dll", &handle);
    printf("host_version: GetFileVersionInfoSizeW(kernel32) -> %lu\n", (unsigned long)size);
    fflush(stdout);
    if (size == 0) {
        printf("host_version: forwarded call FAILED (gle=%lu)\n", (unsigned long)GetLastError());
        return 1;
    }
    /* Proxy trigger: DllMain spawns thread -> --delay-ms -> LoadLibraryW.
       5s covers the CI delay (1000ms) with generous slack. */
    Sleep(5000);
    printf("host_version: done\n");
    return 0;
}
