/*
 * Stub advapi32.dll for Qiling selftest runs.
 *
 * nyx_selftest_hostinfo -> hostinfo::username() force-loads advapi32.dll via
 * LoadLibraryA and resolves GetUserNameW through the PEB walk. Qiling has no
 * hook_GetUserNameW, so the runner registers a set_api("GetUserNameW", ...)
 * override that writes "qiling" (UTF-16) into the caller's buffer — the
 * implant's username() then returns a non-"user" value and the selftest's
 * username bit passes. The export exists here so the PEB-walk resolution
 * finds it; the runner's override services the call.
 */

int __stdcall GetUserNameW(unsigned short *lpBuffer, unsigned long *lpnSize) {
    (void)lpBuffer; (void)lpnSize;
    return 0;
}
