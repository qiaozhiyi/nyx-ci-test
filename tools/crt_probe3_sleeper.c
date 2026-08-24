// crt_probe3_sleeper.c — plain-x64 sacrificial target for
// nyx_selftest_crt_probe3 / nyx_selftest_inject_fls / nyx_selftest_inject_pool
// under Win11 ARM64 Prism (2026-08-24). On ARM64 Windows every inbox GUI
// binary is ARM64/ARM64X (a CreateProcess from an x64-emulated parent starts
// them NATIVE ARM64), so the crt_probe2-style "x64-emulated injector →
// x64-emulated target" sub-case needs a self-provided plain-x64 PE. This is
// it: a Sleep loop that stays alive until TerminateProcess (the
// SacrificialProcess drop guard owns that). dllhost.exe was tried first and
// rejected — with no COM task it exits immediately.
//
// The process also holds a thread-pool work item so the kernel creates the
// pool's WORKER FACTORY object: pool party (inject method 0) discovers the
// target's worker factory via the system handle table, and a bare process has
// none until the first work item is submitted.
//
// Build: x86_64-w64-mingw32-gcc -O2 -o nyx_x64_sleeper.exe crt_probe3_sleeper.c
// Deploy: C:\nyx_test\nyx_x64_sleeper.exe on the test VM (CRT3_SLEEPER path in
// selftests.rs).
#include <windows.h>

static VOID CALLBACK work_cb(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WORK work)
{
    (void)instance;
    (void)context;
    (void)work;
}

int main(void)
{
    PTP_POOL pool = CreateThreadpool(NULL);
    if (pool) {
        TP_CALLBACK_ENVIRON env;
        // mingw-w64 spells the callback-environ inlines TpInitializeCallback-
        // Environ / TpSetCallbackThreadpool (no underscore after TP).
        TpInitializeCallbackEnviron(&env);
        TpSetCallbackThreadpool(&env, pool);
        PTP_WORK work = CreateThreadpoolWork(work_cb, NULL, &env);
        if (work) {
            SubmitThreadpoolWork(work); // forces worker-factory creation
        }
    }
    for (;;) {
        Sleep(60 * 1000);
    }
    return 0;
}
