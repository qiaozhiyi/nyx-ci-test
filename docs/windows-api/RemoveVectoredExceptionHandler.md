# RemoveVectoredExceptionHandler function (errhandlingapi.h) - Win32 apps

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

Unregisters a vectored exception handler.

## Syntax

```c
ULONG RemoveVectoredExceptionHandler(
  PVOID Handle
);
```

## Parameters

### Handle
A handle to the vectored exception handler previously registered using the `AddVectoredExceptionHandler` function.

## Return value

If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero.

## Remarks

To compile an application that uses this function, define the `_WIN32_WINNT` macro as `0x0500` or later. For more information, see [Using the Windows Headers](https://learn.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers).

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

- [AddVectoredExceptionHandler function](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [Vectored Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)

Source: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredexceptionhandler
