/* Minimal reflective-load fixture: DllMain returns TRUE, writes a marker file. */
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE f = CreateFileA("C:\\nyx_probe_fixture_loaded.txt", GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(f, "fixture-dllmain-ok\n", 19, &w, NULL);
            CloseHandle(f);
        }
    }
    return TRUE;
}
