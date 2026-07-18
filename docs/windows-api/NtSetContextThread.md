# NtSetContextThread

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

> **Note**: The official Microsoft documentation for this page returned a 404 error. This is a kernel-mode undocumented/semi-documented NT API. The information below is compiled from public sources (ReactOS, Process Hacker, and Windows internals research).

## Summary

`NtSetContextThread` sets the context of a specified thread. This is a native NT API typically called from kernel mode, but can be invoked from user mode via `NtDll.dll`.

## Prototype (NT Internal)

```c
NTSTATUS NtSetContextThread(
  _In_ HANDLE   ThreadHandle,
  _In_ PCONTEXT ContextRecord
);
```

## Parameters

### ThreadHandle
A handle to the thread whose context is to be set. The handle must have `THREAD_SET_CONTEXT` access rights.

### ContextRecord
A pointer to a [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) structure containing the new context for the thread.

## Return Value

Returns an `NTSTATUS` status code:
- `STATUS_SUCCESS` (0x00000000) — Success
- Other NTSTATUS codes on failure

## User-Mode Equivalent

The documented user-mode equivalent is:

```c
BOOL SetThreadContext(
  HANDLE              hThread,
  const CONTEXT       *lpContext
);
```

## Use Cases

- **Debugging**: Setting register values for breakpoints, single-stepping
- **Exception handling**: Modifying execution context within exception handlers
- **Thread hijacking**: Redirecting thread execution to arbitrary code
- **Anti-debugging research**: Understanding how debuggers manipulate thread state

## Important Notes

- The thread must be in a **suspended** state for the context to take effect reliably.
- Modifying `Rip`/`Eip` changes where the thread will resume execution.
- Modifying `Rsp`/`Esp` changes the thread's stack pointer.
- This API is not officially documented by Microsoft for user-mode consumption.
- The preferred user-mode API is `SetThreadContext` from Kernel32.dll.

## See Also

- [NtGetContextThread](./NtGetContextThread.md) — Retrieve thread context
- [CONTEXT Structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) — Register data structure
- [SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)
- [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

## References

- ReactOS source: `ntdll/ntsys/NtSetContextThread.c`
- Process Hacker kernel plugin
- Windows Internals (7th Edition), Chapter 5

Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetcontextthread (page not publicly available)
