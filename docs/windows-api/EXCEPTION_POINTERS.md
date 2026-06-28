# EXCEPTION_POINTERS (winnt.h) - Win32 apps

Contains an exception record with a machine-independent description of an exception and a context record with a machine-dependent description of the processor context at the time of the exception.

## Syntax

```c
typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
```

## Members

### ExceptionRecord
A pointer to an [EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record) structure that contains a machine-independent description of the exception.

### ContextRecord
A pointer to a [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) structure that contains a processor-specific description of the state of the processor at the time of the exception.

## Usage

The `EXCEPTION_POINTERS` structure is typically obtained via the `GetExceptionInformation()` macro, which is available only within the filter expression of a `__except` handler:

```c
__except (
    // GetExceptionInformation() returns PEXCEPTION_POINTERS
    some_filter_func(GetExceptionInformation())
) {
    // Exception handling code
}
```

Or as the parameter passed to vectored exception handlers registered via `AddVectoredExceptionHandler`.

## Requirements

| Requirement | Value |
|---|---|
| Minimum supported client | Windows XP [desktop apps only] |
| Minimum supported server | Windows Server 2003 [desktop apps only] |
| Header | winnt.h (include Windows.h) |

## See also

- [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
- [EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [GetExceptionInformation](https://learn.microsoft.com/en-us/cpp/intrinsics/getexceptioninformation)

Source: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers
