# NtGetContextThread

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

> **Note**: The official Microsoft documentation for this page returned a 404 error. This is a kernel-mode undocumented/semi-documented NT API. The information below is compiled from public sources (ReactOS, Process Hacker, and Windows internals research).

## Summary

`NtGetContextThread` retrieves the context of a specified thread. This is a native NT API typically called from kernel mode, but can be invoked from user mode via `NtDll.dll`.

## Prototype (NT Internal)

```c
NTSTATUS NtGetContextThread(
  _In_  HANDLE   ThreadHandle,
  _Out_ PCONTEXT ContextRecord
);
```

## Parameters

### ThreadHandle
A handle to the thread for which context information is to be retrieved. The handle must have `THREAD_GET_CONTEXT` access rights.

### ContextRecord
A pointer to a [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) structure that receives the context of the thread.

## Return Value

Returns an `NTSTATUS` status code:
- `STATUS_SUCCESS` (0x00000000) — Success
- Other NTSTATUS codes on failure

## User-Mode Equivalent

The documented user-mode equivalent is:

```c
BOOL GetThreadContext(
  HANDLE    hThread,
  LPCONTEXT lpContext
);
```

With `lpContext->ContextFlags` set to control which register groups to retrieve.

## ContextFlags Values

| Flag | Meaning |
|---|---|
| `CONTEXT_AMD64` (0x00100000) | Context is for AMD64/x64 |
| `CONTEXT_CONTROL` | SegSs, Rsp, SegCs, Rip, EFlags |
| `CONTEXT_INTEGER` | Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, R8–R15 |
| `CONTEXT_SEGMENTS | SegDs, SegEs, SegFs, SegGs |
| `CONTEXT_FLOATING_POINT` | FPU/XMM registers |
| `CONTEXT_DEBUG_REGISTERS` | Dr0–Dr7 |
| `CONTEXT_FULL` (CONTROL \| INTEGER \| FLOATING_POINT) | Full register set |
| `CONTEXT_ALL` (all above) | Everything |

## Notes

- This API is not officially documented by Microsoft for user-mode consumption.
- The preferred user-mode API is `GetThreadContext` from Kernel32.dll.
- This function is often used by anti-debugging and exception handling research.
- See also: `NtSetContextThread`

## References

- ReactOS source: `ntdll/ntsys/NtGetContextThread.c`
- Process Hacker kernel plugin
- Windows Internals (7th Edition), Chapter 5

Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntgetcontextthread (page not publicly available)
