# AddVectoredExceptionHandler function (errhandlingapi.h) - Win32 apps

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

Registers a vectored exception handler.

## Syntax

```c
PVOID AddVectoredExceptionHandler(
  ULONG                       First,
  PVECTORED_EXCEPTION_HANDLER Handler
);
```

## Parameters

### First
The order in which the handler should be called. If the parameter is nonzero, the handler is the first handler to be called. If the parameter is zero, the handler is the last handler to be called.

### Handler
A pointer to the handler to be called. For more information, see VectoredHandler.

## Return value

If the function succeeds, the return value is a handle to the exception handler.

If the function fails, the return value is NULL.

## Remarks

- If the `First` parameter is nonzero, the handler is the first handler to be called until a subsequent call to `AddVectoredExceptionHandler` is used to specify a different handler as the first handler.
- If the VectoredHandler parameter points to a function in a DLL and that DLL is unloaded, the handler is still registered. This can lead to application errors.
- To unregister the handler, use the `RemoveVectoredExceptionHandler` function.
- To compile an application that uses this function, define the `_WIN32_WINNT` macro as `0x0500` or later.

## Examples

For an example, see [Using a Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler).

## Requirements

| Requirement | Value |
|---|---|
| Minimum supported client | Windows XP [desktop apps only] |
| Minimum supported server | Windows Server 2003 [desktop apps only] |
| Target Platform | Windows |
| Header | errhandlingapi.h (include Windows.h) |
| Library | Kernel32.lib |
| DLL | Kernel32.dll |

## See also

- [AddVectoredContinueHandler function](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredcontinuehandler)
- [RemoveVectoredExceptionHandler function](https://learn.microsoft.com/en-us/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredexceptionhandler)
- [Vectored Exception Handling](https://learn.microsoft.com/en-us/win32/debug/vectored-exception-handling)
- [VectoredHandler](https://learn.microsoft.com/en-us/win32/debug/vectoredhandler)

## Nyx 注记 — PEB-walk 解析陷阱（PIC implant 专用）

> This function is a **forwarded export** in `kernel32.dll` → `NTDLL.RtlAddVectoredExceptionHandler`.
> In Nyx's position-independent implant there is no IAT/loader help; `resolve::export_addr`
> PEB-walks the export table and must resolve the forwarder. **A forwarder bug here was the root
> cause of a 0xC0000005 crash** (the resolved "address" pointed at the ASCII forwarder string
> `"NTDLL.RtlAddVectored..."` instead of code → calling it AV'd). See
> `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`.
>
> **Diagnostic:** if a `resolve::export_addr`-returned address AV's on call, dump 16 bytes at it;
> printable ASCII (`NTDLL.`, `KERNELBASE.`, `api-ms-...`) = a forwarder string, not code. The fix
> lives in `resolve.rs::{export_addr_by_hash_pub, resolve_forwarder, find_module_for_forwarder}`
> and is guarded by `nyx_selftest_resolve_forwarder` (exit=7).

Source: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler
