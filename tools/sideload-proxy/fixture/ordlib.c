/* Ordinal-only fixture DLL for the proxy ordinal-forwarder stage.
 *
 * Exported by ordinal 1 WITHOUT a name (see ordlib.def, NONAME) so the
 * generator must emit `"_ord_1" = "orddll_orig.#1" @1 NONAME` — the path
 * goblin would have dropped (see pe_exports.rs rationale). Runtime proof
 * target: GetProcAddress(proxy, #1) chains to orddll_orig.#1 under the real
 * Windows loader.
 *
 * Build (mingw):  x86_64-w64-mingw32-gcc -shared -O2 ordlib.c ordlib.def -o orddll.dll
 */
int __stdcall ord_answer(void) { return 42; }
