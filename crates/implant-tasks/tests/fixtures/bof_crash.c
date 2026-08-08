/* Deliberately-faulting BOF: B3 isolated-mode (child-process) selftest
 * fixture. Compiled to bof_crash.o (COFF) with the same recipe as the
 * bof_print.o / bof_marker.o fixtures:
 *   x86_64-w64-mingw32-gcc -c bof_crash.c -o bof_crash.o
 *
 * go() stores to the null page (address 0 is always unmapped — the
 * null-pointer assignment partition), raising STATUS_ACCESS_VIOLATION in
 * whatever process executes it. Run INLINE this would kill the beacon; the
 * point of the B3 isolated path is that only the sacrificial child dies and
 * the parent maps the nonzero exit to Response::Err. The volatile store is
 * a real memory access: the compiler may not elide it or fold it into a
 * trap (same discipline as the task_guard selftest's write_volatile). No
 * BeaconPrintf call — a faulting child must never produce the success
 * marker.
 */
void go(char *args, int len)
{
    (void)args;
    (void)len;
    *(volatile unsigned long *)0 = 0x41414141UL;
}
