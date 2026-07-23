/* Test BOF: calls the Beacon-API shim's BeaconPrintf to produce captured
 * output. Compiled to bof_print.o (COFF) for the runner demo. */
extern void BeaconPrintf(int type, const char *fmt, ...);
void go(void) { BeaconPrintf(0x0, "BOF-PRINT-OK %d\n", 42); }
