/* Minimal Beacon-API shim, compiled (via build.rs) into the Windows agent so
 * BOFs that call BeaconPrintf produce captured output. Only the subset a first
 * cut needs; extend per the CS Beacon ABI as required.
 *
 *   void BeaconPrintf(int type, const char* fmt, ...)  // CS ABI
 */
#include <stdarg.h>
#include <stdio.h>

#define NYX_OUT_CAP 16384
static char nyx_out[NYX_OUT_CAP];
static int  nyx_len = 0;

void nyx_bof_reset(void) {
    nyx_len = 0;
    nyx_out[0] = 0;
}

const char *nyx_bof_output(void) {
    return nyx_out;
}

/* CS CALLBACK_OUTPUT = 0x0. We ignore `type` for formatting (capture all). */
void BeaconPrintf(int type, const char *fmt, ...) {
    (void)type;
    va_list ap;
    va_start(ap, fmt);
    if (nyx_len < NYX_OUT_CAP - 1) {
        int n = vsnprintf(nyx_out + nyx_len, NYX_OUT_CAP - nyx_len, fmt, ap);
        if (n > 0) nyx_len += n;
    }
    va_end(ap);
}
