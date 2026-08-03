// Minimal reflective-load fixture DLL for the Unicorn full-blob probe.
//
// Deliberately imports a few kernel32 APIs so the pic-loader's import
// resolution path (LoadLibraryA + GetProcAddress → IAT patching) is exercised
// end-to-end in the emulator: GetModuleHandleA (PEB-adjacent lookup) and
// CreateFileA (a "payload behavior" import that is NOT in the synthetic OS's
// export table — it must resolve through the emu's wildcard stub).
//
// DllMain itself only returns TRUE (the loader contract); it must not depend
// on any import succeeding semantically, only on the IAT being populated.

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    /* Force the import table to include these (they are otherwise never
       referenced and mingw -nostdlib would emit no imports at all): */
    GetModuleHandleA(NULL);
    CreateFileA(NULL, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    return TRUE;
}
