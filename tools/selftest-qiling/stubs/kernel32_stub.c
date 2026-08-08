/*
 * Stub kernel32.dll for Qiling selftest runs.
 *
 * The implant resolves every Win32 API through a PEB-walk + export-table hash
 * lookup (crates/implant-core/src/resolve.rs) and calls the export address
 * directly. Qiling intercepts those direct calls with a code hook
 * (ql.hook_code -> hook_winapi) that dispatches to its Python API
 * implementations by export name, so the stub functions here are NEVER
 * executed: they only need to exist so the export table carries the names the
 * selftests resolve. Keeping the set minimal means an API Qiling does not
 * implement can never be reached through a PEB-walk (its absence surfaces as
 * a graceful resolution failure inside the implant instead of a crash).
 *
 * Exports required by the qiling selftest matrix:
 *   nyx_selftest_calib42 : ExitProcess
 *   nyx_selftest_env     : GetEnvironmentStringsW, FreeEnvironmentStringsW,
 *                          GetEnvironmentVariableW, ExitProcess
 *   nyx_selftest_config  : ExitProcess
 *   nyx_selftest_hostinfo: GetComputerNameW, GetCurrentProcessId,
 *                          GetSystemTimeAsFileTime, LoadLibraryA, ExitProcess
 * (advapi32!GetUserNameW lives in advapi32_stub.c)
 *
 * Bodies return 0; qiling's hook_* implementation for the same name takes
 * over at call time.
 */

void __stdcall ExitProcess(unsigned int uExitCode) { (void)uExitCode; }

unsigned short *__stdcall GetEnvironmentStringsW(void) { return 0; }

int __stdcall FreeEnvironmentStringsW(unsigned short *penv) { (void)penv; return 0; }

unsigned long __stdcall GetEnvironmentVariableW(const unsigned short *lpName,
                                                unsigned short *lpBuffer,
                                                unsigned long nSize) {
    (void)lpName; (void)lpBuffer; (void)nSize;
    return 0;
}

int __stdcall GetComputerNameW(unsigned short *lpBuffer, unsigned long *lpnSize) {
    (void)lpBuffer; (void)lpnSize;
    return 0;
}

unsigned long __stdcall GetCurrentProcessId(void) { return 0; }

void __stdcall GetSystemTimeAsFileTime(void *lpFileTime) { (void)lpFileTime; }

void *__stdcall LoadLibraryA(const char *lpLibFileName) { (void)lpLibFileName; return 0; }
