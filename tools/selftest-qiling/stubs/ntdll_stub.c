/*
 * Stub ntdll.dll for Qiling selftest runs.
 *
 * The implant's global allocator (crates/implant-core/src/ntalloc.rs) resolves
 * RtlCreateHeap + RtlAllocateHeap (+ RtlFreeHeap/RtlReAllocateHeap) through
 * the PEB walk. Qiling implements hook_RtlAllocateHeap (allocates from its own
 * emulated heap) but NOT RtlCreateHeap/RtlFreeHeap, so:
 *   - RtlCreateHeap is exported here so the implant's ensure_heap() succeeds;
 *     the runner registers a set_api("RtlCreateHeap", ...) override that
 *     returns a dummy non-null handle (qiling's RtlAllocateHeap ignores it).
 *   - RtlAllocateHeap is exported and serviced by qiling itself.
 *   - RtlFreeHeap / RtlReAllocateHeap are deliberately NOT exported: the
 *     implant's dealloc path treats a failed resolution as a no-op (no crash),
 *     while a resolvable-but-unimplemented export would fall through to real
 *     DLL code and fault under emulation.
 */

void *__stdcall RtlCreateHeap(unsigned long Flags, void *HeapBase,
                              unsigned long ReserveSize, unsigned long CommitSize,
                              void *Lock, void *Parameters) {
    (void)Flags; (void)HeapBase; (void)ReserveSize; (void)CommitSize;
    (void)Lock; (void)Parameters;
    return 0;
}

void *__stdcall RtlAllocateHeap(void *HeapHandle, unsigned long Flags,
                                unsigned long Size) {
    (void)HeapHandle; (void)Flags; (void)Size;
    return 0;
}

/*
 * CRT mem functions. The mingw-linked selftest DLL routes memcpy/memset/
 * memcmp/strlen through api-ms-win-crt-* IAT entries; qiling redirects those
 * to key DLLs (ntdll first) when the symbol exists there, then dispatches the
 * call to its Python hooks. hook_memcpy is implemented by qiling; memset,
 * memcmp and strlen are serviced by set_api overrides in runner.py.
 */

void *__stdcall memcpy(void *dest, const void *src, unsigned long long count) {
    (void)dest; (void)src; (void)count;
    return 0;
}

void *__stdcall memset(void *dest, int val, unsigned long long count) {
    (void)dest; (void)val; (void)count;
    return 0;
}

int __stdcall memcmp(const void *a, const void *b, unsigned long long count) {
    (void)a; (void)b; (void)count;
    return 0;
}

unsigned long long __stdcall strlen(const char *s) {
    (void)s;
    return 0;
}
