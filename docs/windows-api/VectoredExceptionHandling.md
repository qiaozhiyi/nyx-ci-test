# Vectored Exception Handling - Win32 apps

Vectored exception handlers are an extension to structured exception handling. An application can register a function to watch or handle all exceptions for the application. Vectored handlers are not frame-based, therefore, you can add a handler that will be called regardless of where you are in a call frame. Vectored handlers are called in the order that they were added, after the debugger gets a first chance notification, but before the system begins unwinding the stack.

## Key Functions

- **AddVectoredContinueHandler** / **RemoveVectoredContinueHandler** — Add or remove a vectored continue handler.
- **AddVectoredExceptionHandler** / **RemoveVectoredExceptionHandler** — Add or remove a vectored exception handler.

## Overview

Vectored exception handling provides a mechanism for handling exceptions that is simpler and more flexible than the frame-based structured exception handling (SEH) model. Key characteristics:

1. **Non-frame-based**: Handlers are called regardless of where you are in the call frame hierarchy.
2. **Ordered callbacks**: Handlers are called in the order they were registered.
3. **Debugger notification first**: Vectored handlers are called after the debugger gets a first-chance notification.
4. **Pre-unwind**: Vectored handlers execute before the system begins unwinding the stack.

## Handler Types

### Vectored Exception Handler
- Registered via `AddVectoredExceptionHandler`
- Receives `EXCEPTION_POINTERS` parameter
- Can handle, modify, or pass exceptions

### Vectored Continue Handler
- Registered via `AddVectoredContinueHandler`
- Called during exception continuation (after `CONTINUE_SEARCH` or `CONTINUE_EXECUTION`)
- Useful for monitoring continue-execution decisions

## Related Structures

- [EXCEPTION_POINTERS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers)
- [EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)

## Handler Priority

Handlers are called in this order:
1. Debugger first-chance notification
2. Vectored exception handlers (in registration order, `First=1` handlers before `First=0`)
3. Frame-based SEH handlers (try/except)
4. System stack unwinding

## Example Usage

```c
#include <windows.h>
#include <stdio.h>

LONG WINAPI VectoredHandler(EXCEPTION_POINTERS *ExceptionInfo) {
    printf("Exception code: 0x%08X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    printf("Exception address: %p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
    
    // Return EXCEPTION_CONTINUE_SEARCH to let other handlers process it
    // Return EXCEPTION_CONTINUE_EXECUTION to resume execution
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    // Register as first handler (First=1)
    PVOID handler = AddVectoredExceptionHandler(1, VectoredHandler);
    
    if (handler) {
        // ... application code ...
        
        // Unregister when done
        RemoveVectoredExceptionHandler(handler);
    }
    
    return 0;
}
```

## Source

- https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling
- https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling-portal
